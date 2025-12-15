#
#  Script for piping a local serial connection to a TCP port.
#
#  Copyright (c) Microsoft Corporation.
#  SPDX-License-Identifier: BSD-2-Clause-Patent
#

import argparse
import logging
import pywintypes
import queue
import serial
import socket
import threading
import time
import win32file
from datetime import datetime
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument(
    "-l",
    "--log-path",
    type=str,
    help="File path or directory for serial logs. "
    "If a file, logs to that file. "
    "If a directory, creates timestamped log files.",
)
parser.add_argument(
    "--script-log-file",
    type=str,
    help="File path to write script operational logs (info, errors, etc.).",
)
parser.add_argument(
    "-p",
    "--port",
    type=int,
    default=5555,
    help="The TCP port to listen for connections.",
)
parser.add_argument(
    "-n", "--pipe", type=str, help="The named pipe to connect to connect to."
)
parser.add_argument(
    "-c",
    "--comport",
    type=str,
    help="The number of the COM device to connect to. E.G 'COM5'",
)
parser.add_argument(
    "-b",
    "--baudrate",
    type=int,
    default=115200,
    help="The baudrate of the serial port.",
)
parser.add_argument(
    "-s",
    "--show",
    action="store_true",
    help="Shows all serial traffic (including debugger) on the console.",
)
parser.add_argument(
    "-d", "--debug", action="store_true", help="Enables debug printing."
)
parser.add_argument(
    "--show-direction",
    action="store_true",
    help="Prefix log entries with direction indicator (IN/OUT).",
)
args = parser.parse_args()

# Constants
BUFFER_SIZE = 4096 * 2
SERIAL_CHUNK_SIZE = 32
SERIAL_CHUNK_DELAY = 0.00025

# Global queues used between threads.
out_queue = queue.Queue()
in_queue = queue.Queue()

# Loggers
script_logger = logging.getLogger("script")
serial_logger = logging.getLogger("serial")

# Buffers for incomplete lines
_line_buffer_in = ""
_line_buffer_out = ""


def socket_thread() -> None:
    """Thread function that handles TCP socket connections.

    Creates a TCP server socket that listens for connections and manages
    bidirectional data transfer between the socket and serial connection.
    Data received from the socket is placed in in_queue, and data from
    out_queue is sent to the socket.

    The function runs indefinitely, accepting new connections as they arrive.
    """
    # Set up the socket.
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("", args.port))
    sock.listen()

    while True:
        script_logger.info("Waiting for socket...")
        conn, addr = sock.accept()
        script_logger.info(f"Socket Connected - {addr}")

        # clear the out queue before starting a connection
        while not out_queue.empty():
            out_queue.get()

        # use a short timeout to move on if no data is ready.
        conn.settimeout(0.01)

        # process the queue.
        connected = True
        while connected:
            try:
                while not out_queue.empty():
                    conn.sendall(out_queue.get())

                data = conn.recv(BUFFER_SIZE)
            except socket.timeout:
                data = None
            except Exception:
                script_logger.info("Socket disconnected.")
                connected = False
                continue

            if data is not None and len(data) != 0:
                in_queue.put(data)


def log_serial_data(inout: bool, data: bytes) -> None:
    """Log serial data without modification.

    Args:
        inout: True if data is incoming (to serial port),
               False if outgoing (from serial port)
        data: The bytes to log
    """
    global _line_buffer_in, _line_buffer_out

    text = data.decode("ascii", errors="replace")

    if inout:
        buffer = _line_buffer_in
    else:
        buffer = _line_buffer_out

    buffer += text
    lines = buffer.split('\n')
    buffer = lines[-1]

    # Log all complete lines
    for line in lines[:-1]:
        # Remove trailing carriage return if present to prevent double spacing
        # in the log file.
        line = line.rstrip('\r')
        if args.show_direction:
            direction = "IN " if inout else "OUT"
            serial_logger.info(f"[{direction}] {line}")
        else:
            serial_logger.info(line)

    if inout:
        _line_buffer_in = buffer
    else:
        _line_buffer_out = buffer


def listen_named_pipe() -> None:
    """Listen to a Windows named pipe for serial data.

    Continuously reads data from the named pipe specified in args.pipe
    and forwards it to the TCP socket via out_queue. Data received from
    the TCP socket (via in_queue) is written to the named pipe.

    The function handles pipe connection errors and will retry connection
    if the pipe is not yet available.
    """
    script_logger.info("Waiting for pipe...")
    quit = False
    while not quit:
        try:
            handle = win32file.CreateFile(
                args.pipe,
                win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                0,
                None,
                win32file.OPEN_EXISTING,
                0,
                None,
            )

            script_logger.info("Pipe connected.")
            while True:
                if win32file.GetFileSize(handle) > 0:
                    hr, data = win32file.ReadFile(handle, BUFFER_SIZE)
                    if hr != 0:
                        script_logger.error(f"Error reading: {hr}")
                        continue

                    log_serial_data(False, data)
                    out_queue.put(data)

                while not in_queue.empty():
                    data = in_queue.get()
                    log_serial_data(True, data)
                    win32file.WriteFile(handle, data, None)

        except pywintypes.error as e:
            if e.args[0] == 2:
                if args.debug:
                    script_logger.debug("No pipe yet, waiting...")
                time.sleep(1)
            elif e.args[0] == 109:
                script_logger.error("broken pipe")
                quit = True


def listen_com_port() -> None:
    """Listen to a COM serial port for data.

    Opens the COM port specified in args.comport with the baudrate from
    args.baudrate. Continuously reads data from the serial port and
    forwards it to the TCP socket via out_queue. Data received from the
    TCP socket (via in_queue) is written to the serial port in chunks
    to avoid overwhelming the FIFO buffer.

    The serial port is configured with 8 data bits, no parity, and
    1 stop bit.
    """
    script_logger.info("Opening com port...")
    serial_port = serial.Serial(
        args.comport,
        args.baudrate,
        parity=serial.PARITY_NONE,
        stopbits=serial.STOPBITS_ONE,
        bytesize=serial.EIGHTBITS,
        timeout=0.1,
    )

    script_logger.info(f"Opened {args.comport}.")
    while True:
        if serial_port.in_waiting > 0:
            data = serial_port.read(size=serial_port.in_waiting)
            log_serial_data(False, data)
            out_queue.put(data)

        while not in_queue.empty():
            data = in_queue.get()
            log_serial_data(True, data)

            for i in range(0, len(data), SERIAL_CHUNK_SIZE):
                chunk = data[i:i + SERIAL_CHUNK_SIZE]
                serial_port.write(chunk)
                # a short delay to avoid overwhelming the FIFO. This
                # should be solvable with RTS flow control, but that
                # doesn't seem to work on Patina's 16550 implementation.
                time.sleep(SERIAL_CHUNK_DELAY)


def setup_logging() -> None:
    """Configure logging for script and serial loggers.

    Sets up handlers and formatters based on command-line arguments:
    - Script logger: operational logs (info, errors, etc.)
    - Serial logger: all serial port data

    Log files are written to:
    - Script log: --script-log-file if specified
    - Serial log: --log-path (filename or directory with timestamped file)
    """
    # Console handler for script logger (always enabled)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG if args.debug else logging.INFO)
    console_formatter = logging.Formatter('%(message)s')
    console_handler.setFormatter(console_formatter)

    script_logger.setLevel(logging.DEBUG if args.debug else logging.INFO)
    script_logger.addHandler(console_handler)

    # Add file handler for script logging if specified
    if args.script_log_file:
        script_file_handler = logging.FileHandler(
            args.script_log_file, mode='w'
        )
        script_file_handler.setLevel(
            logging.DEBUG if args.debug else logging.INFO
        )
        script_file_formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        script_file_handler.setFormatter(script_file_formatter)
        script_logger.addHandler(script_file_handler)

    serial_logger.setLevel(logging.INFO)

    # Create file handler if log path is specified
    if args.log_path:
        log_path = Path(args.log_path)

        # Consider the path a file if it has a suffix
        if log_path.suffix:
            serial_file = log_path
            log_dir = log_path.parent
            if log_dir and not log_dir.exists():
                log_dir.mkdir(parents=True, exist_ok=True)
        else:
            log_dir = log_path
            log_dir.mkdir(parents=True, exist_ok=True)

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            serial_file = log_dir / f"log_{timestamp}.log"

        serial_file_handler = logging.FileHandler(serial_file, mode='w')
        serial_file_handler.setLevel(logging.INFO)
        serial_formatter = logging.Formatter('%(message)s')
        serial_file_handler.setFormatter(serial_formatter)
        serial_logger.addHandler(serial_file_handler)

        script_logger.info(f"Logging serial data to: {serial_file}")

    if args.show:
        serial_console = logging.StreamHandler()
        serial_console.setLevel(logging.INFO)
        serial_console.setFormatter(console_formatter)
        serial_logger.addHandler(serial_console)


def main() -> None:
    """Main entry point for the COM to TCP bridge server.

    Validates command-line arguments, configures logging,
    starts the TCP socket thread, and begins listening on either a
    named pipe or COM port based on the provided arguments.

    The function requires either --pipe or --comport to be specified.
    """
    if args.pipe is None and args.comport is None:
        print("Must specify a serial connection!")
        return

    setup_logging()

    script_logger.info("COM to TCP Bridge Server")
    script_logger.info(f"Arguments: {args}")

    # Create the thread for the TCP port.
    port_thread = threading.Thread(target=socket_thread)
    port_thread.daemon = True
    port_thread.start()

    try:
        if args.pipe is not None:
            listen_named_pipe()
        if args.comport is not None:
            listen_com_port()
        else:
            raise Exception("No serial port to connect to!")
    except KeyboardInterrupt:
        script_logger.info("Exiting due to a keyboard interrupt.")
    except Exception as e:
        script_logger.error(f"An error occurred: {e}")


main()
