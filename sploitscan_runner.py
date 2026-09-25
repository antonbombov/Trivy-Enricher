# sploitscan_runner.py
import os
import subprocess
import sys
import time
import shutil
import threading
from pathlib import Path
from config_manager import get_sploitscan_path, load_config


def find_existing_json(cve_id, target_dir):
    """Ищет существующий JSON файл для CVE в кэше"""
    json_files = list(target_dir.glob(f"*{cve_id}*.json"))
    if json_files:
        return json_files[0]
    return None


def setup_sploitscan_logging(cve_id, attempt):
    """Настраивает логирование вывода sploitscan для конкретного CVE и попытки"""
    config = load_config()
    output_dir = Path(config.get('output_directory', 'Results'))

    # Создаем папку logs внутри output_directory
    log_dir = output_dir / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)

    # Создаем уникальный лог-файл для каждой попытки CVE
    log_file = log_dir / f"sploitscan_{cve_id}_attempt{attempt}.log"
    return log_file


def read_output(process, log_file):
    """Читает вывод процесса в реальном времени и пишет в лог"""
    try:
        with open(log_file, 'a', encoding='utf-8') as log_f:
            while True:
                output = process.stdout.readline()
                if output == '' and process.poll() is not None:
                    break
                if output:
                    log_f.write(output)
                    log_f.flush()
    except Exception as e:
        with open(log_file, 'a', encoding='utf-8') as log_f:
            log_f.write(f"\n*** LOGGING ERROR: {str(e)} ***\n")


def run_sploitscan(cve_id, target_dir, attempt=1):
    """
    Запускает sploitscan для CVE (кросс-платформенно)
    attempt - номер попытки (для логирования)

    ВАЖНО: SploitScan запускается с cwd=target_dir, чтобы он писал
    свой JSON сразу в папку кэша (а не в /sploitscan/).
    """
    try:
        config = load_config()
        sploitscan_path = get_sploitscan_path(config)

        if not sploitscan_path:
            return {'status': 'failed', 'error': 'SploitScan не найден'}

        # Создаем целевую папку (кэш)
        target_dir.mkdir(parents=True, exist_ok=True)

        # Проверяем кэш (только для первой попытки)
        if attempt == 1:
            existing_file = find_existing_json(cve_id, target_dir)
            if existing_file:
                return {'status': 'cached', 'file': existing_file, 'execution_time': 0}

        # Настраиваем логирование для этого CVE и попытки
        log_file = setup_sploitscan_logging(cve_id, attempt)

        # Настраиваем окружение
        env = os.environ.copy()
        env['PYTHONIOENCODING'] = 'utf-8'
        env['PYTHONUTF8'] = '1'

        # Определяем команду
        if sploitscan_path.endswith('.py'):
            cmd = ['python', sploitscan_path, "-e", "json", cve_id]
            sploitscan_dir = Path(sploitscan_path).parent
        else:
            cmd = [sploitscan_path, "-e", "json", cve_id]
            sploitscan_dir = Path(sploitscan_path).parent

        # Добавляем директорию SploitScan в PYTHONPATH,
        # чтобы Python нашёл модули sploitscan.* даже при запуске из другой cwd
        existing_pythonpath = env.get('PYTHONPATH', '')
        if existing_pythonpath:
            env['PYTHONPATH'] = f"{sploitscan_dir}{os.pathsep}{existing_pythonpath}"
        else:
            env['PYTHONPATH'] = str(sploitscan_dir)

        # КЛЮЧЕВОЕ: запускаем SploitScan с рабочей директорией = target_dir (кэш).
        # Тогда SploitScan пишет "./xxx_export.json" прямо в кэш,
        # а не в /sploitscan/ (где под --user нет прав).
        run_cwd = target_dir

        # Записываем информацию о запуске
        with open(log_file, 'w', encoding='utf-8') as log_f:
            log_f.write(f"=== SploitScan execution for {cve_id} ===\n")
            log_f.write(f"Attempt: {attempt}\n")
            log_f.write(f"Command: {' '.join(cmd)}\n")
            log_f.write(f"SploitScan dir: {sploitscan_dir}\n")
            log_f.write(f"Working directory (cwd): {run_cwd}\n")
            log_f.write(f"PYTHONPATH: {env['PYTHONPATH']}\n")
            log_f.write(f"Start time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            log_f.write(f"Timeout: {config.get('timeout', 60)} seconds\n")
            log_f.write("=" * 50 + "\n\n")
            log_f.flush()

        # Запускаем sploitscan с записью вывода в реальном времени
        start_time = time.time()

        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            encoding='utf-8',
            env=env,
            cwd=str(run_cwd),           # ← ИЗМЕНЕНО: было cwd=str(cwd)
            bufsize=1,
            universal_newlines=True
        )

        log_thread = threading.Thread(target=read_output, args=(process, log_file))
        log_thread.daemon = True
        log_thread.start()

        try:
            returncode = process.wait(timeout=config.get('timeout', 60))
            execution_time = time.time() - start_time

            log_thread.join(timeout=5)

            with open(log_file, 'a', encoding='utf-8') as log_f:
                log_f.write(f"\n" + "=" * 50 + "\n")
                log_f.write(f"Return code: {returncode}\n")
                log_f.write(f"End time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                log_f.write(f"Execution time: {execution_time:.2f}s\n")

            if returncode == 0:
                # Ищем созданный файл в target_dir (там же, где запускался SploitScan)
                json_files = list(run_cwd.glob(f"*{cve_id}*.json"))

                if json_files:
                    source_file = json_files[0]
                    # Файл уже в кэше — просто возвращаем путь
                    return {
                        'status': 'success',
                        'file': source_file,
                        'execution_time': execution_time,
                        'attempt': attempt
                    }
                else:
                    return {
                        'status': 'failed',
                        'error': 'JSON файл не создан',
                        'execution_time': execution_time,
                        'attempt': attempt
                    }
            else:
                return {
                    'status': 'failed',
                    'error': f'Process exited with code {returncode}',
                    'execution_time': execution_time,
                    'attempt': attempt
                }

        except subprocess.TimeoutExpired:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()

            execution_time = time.time() - start_time

            with open(log_file, 'a', encoding='utf-8') as log_f:
                log_f.write(f"\n\n*** TIMEOUT EXPIRED after {config.get('timeout', 60)} seconds ***\n")
                log_f.write(f"Process was terminated\n")
                log_f.write(f"Partial execution time: {execution_time:.2f}s\n")

            return {
                'status': 'failed',
                'error': 'Timeout expired',
                'execution_time': execution_time,
                'attempt': attempt
            }

    except Exception as e:
        log_file = setup_sploitscan_logging(cve_id, attempt)
        with open(log_file, 'a', encoding='utf-8') as log_f:
            log_f.write(f"\n*** EXCEPTION: {str(e)} ***\n")

        return {'status': 'failed', 'error': str(e), 'attempt': attempt}