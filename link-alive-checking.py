#!/usr/bin/env python3

import argparse
import asyncio
import concurrent.futures
import signal
import random
import socket
import os
import csv
import itertools
import struct
import datetime

STREAM_READER_LIMIT = 16777216

class UserError(Exception):
    pass

def dt_to_nanos(dt):
    return int(
        (
            dt
            -
            datetime.datetime.fromtimestamp(0)
        ).total_seconds()
        *
        1000000
    )

def nanos_to_dt(nanos):
    return datetime.datetime.fromtimestamp(0) + \
            datetime.timedelta(seconds=nanos / 1000000)
    
    # or raise OverflowError

def format_dt(dt):
    if dt is None:
        return
    
    return dt.isoformat(' ')

def format_lag_delta(lag_delta):
    if lag_delta is None:
        return
    
    return f'{lag_delta.total_seconds() * 1000}'

def get_peername(writer):
    if writer is None:
        return
    
    return writer.get_extra_info('peername')

class Log:
    def __init__(self, log_prefix):
        self.thread_pool = concurrent.futures.ThreadPoolExecutor(
            max_workers=1
        )
        self.log_prefix = log_prefix
    
    def blocking_write(
                self,
                is_error,
                date_dt,
                event_name,
                event_comment,
                lag_delta,
                con_id,
                client_id,
                pkg_id,
                server_pkg_id,
            ):
        if is_error:
            csv_path_list = \
                    f'{self.log_prefix}.{date_dt.year:0>2}-{date_dt.month:0>2}-{date_dt.day:0>2}.csv', \
                    f'{self.log_prefix}.{date_dt.year:0>2}-{date_dt.month:0>2}-{date_dt.day:0>2}.error.csv'
        else:
            csv_path_list = \
                    f'{self.log_prefix}.{date_dt.year:0>2}-{date_dt.month:0>2}-{date_dt.day:0>2}.csv',
        
        for csv_path in csv_path_list:
            with open(csv_path, mode='a', encoding='utf-8', newline='') as csv_fd:
                os.lockf(csv_fd.fileno(), os.F_LOCK, 0)
                
                csv_writer = csv.writer(csv_fd)
                
                if not csv_fd.tell():
                    csv_writer.writerow((
                        'date_dt',
                        'event_name',
                        'event_comment',
                        'lag_delta',
                        'con_id',
                        'client_id',
                        'pkg_id',
                        'server_pkg_id',
                    ))
                
                csv_writer.writerow((
                    format_dt(date_dt),
                    event_name,
                    event_comment,
                    format_lag_delta(lag_delta),
                    con_id,
                    client_id,
                    pkg_id,
                    server_pkg_id,
                ))
    
    def write(self, *args):
        self.thread_pool.submit(self.blocking_write, *args)
    
    def shutdown(self, wait=None):
        if wait is None:
            wait is True
        
        self.thread_pool.shutdown(wait)

async def process_server_client(loop, client_id, client_reader, client_writer):
    try:
        pkg_counter = itertools.count(1)
        
        while True:
            try:
                in_data = await client_reader.readexactly(8)
            except (EOFError, OSError):
                break
            
            pkg_id = next(pkg_counter)
            date_nanos, = struct.unpack('!Q', in_data)
            out_data = struct.pack('!QQQ', client_id, pkg_id, date_nanos)
            
            try:
                client_writer.write(out_data)
                
                await client_writer.drain()
            except OSError:
                break
    finally:
        client_writer.close()

async def server(loop, host, port):
    client_prefix = random.randrange(10 ** 5) * 10 ** 10
    client_counter = itertools.count(1)
    
    def client_connected(client_reader, client_writer):
        client_id = client_prefix + next(client_counter)
        
        client_writer.get_extra_info('socket').setsockopt(
            socket.SOL_SOCKET,
            socket.SO_KEEPALIVE,
            1
        )
        
        asyncio.ensure_future(
            process_server_client(
                loop,
                client_id,
                client_reader,
                client_writer
            ),
            loop=loop,
        )
    
    server = await asyncio.start_server(
        client_connected,
        host=host,
        port=port,
        loop=loop,
        limit=STREAM_READER_LIMIT,
    )
    
    try:
        await server.wait_closed()
    except asyncio.CancelledError:
        pass
    finally:
        server.close()

async def client(loop, log, host, port, interval):
    log.write(
        False,
        datetime.datetime.now(),
        'client_start',
        f'host={repr(host)} port={repr(port)} interval={repr(interval)}',
        None,
        None,
        None,
        None,
        None,
    )
    
    writer = None
    write_future = None
    con_counter = itertools.count(1)
    con_id = None
    
    def close():
        nonlocal con_id, write_future, writer
        
        log.write(
            False,
            datetime.datetime.now(),
            'close',
            f'peername={repr(get_peername(writer))}',
            None,
            con_id,
            None,
            None,
            None,
        )
        
        con_id = None
        
        if write_future is not None:
            write_future.cancel()
            write_future = None
        
        if writer is not None:
            writer.close()
            writer = None
    
    async def write_thread(target_writer):
        while target_writer is writer:
            date_now_dt = datetime.datetime.now()
            
            date_nanos = dt_to_nanos(date_now_dt)
            out_data = struct.pack('!Q', date_nanos)
            
            try:
                target_writer.write(out_data)
                
                await target_writer.drain()
            except OSError as e:
                log.write(
                    True,
                    datetime.datetime.now(),
                    'write_error',
                    f'{type(e)}: {str(e)} | peername={repr(get_peername(target_writer))}',
                    None,
                    con_id,
                    None,
                    None,
                    None,
                )
                
                close()
                
                return
            
            await asyncio.sleep(interval, loop=loop)
    
    try:
        while True:
            if writer is None:
                log.write(
                    False,
                    datetime.datetime.now(),
                    'connecting',
                    f'host={repr(host)} port={repr(port)} interval={repr(interval)}',
                    None,
                    con_id,
                    None,
                    None,
                    None,
                )
                
                try:
                    reader, writer = await asyncio.open_connection(
                        host=host,
                        port=port,
                        loop=loop,
                        limit=STREAM_READER_LIMIT,
                    )
                except OSError as e:
                    log.write(
                        True,
                        datetime.datetime.now(),
                        'connect_error',
                        f'{type(e)}: {str(e)} | host={repr(host)} port={repr(port)} interval={repr(interval)}',
                        None,
                        con_id,
                        None,
                        None,
                        None,
                    )
                    
                    await asyncio.sleep(interval, loop=loop)
                    
                    continue
                
                con_id = next(con_counter)
                pkg_counter = itertools.count(1)
                
                writer.get_extra_info('socket').setsockopt(
                    socket.SOL_SOCKET,
                    socket.SO_KEEPALIVE,
                    1
                )
                
                write_future = asyncio.ensure_future(
                    write_thread(writer),
                    loop=loop,
                )
                
                log.write(
                    False,
                    datetime.datetime.now(),
                    'connected',
                    f'host={repr(host)} port={repr(port)} interval={repr(interval)} peername={repr(get_peername(writer))}',
                    None,
                    con_id,
                    None,
                    None,
                    None,
                )
            
            try:
                in_data = await reader.readexactly(24)
            except (EOFError, OSError) as e:
                log.write(
                    True,
                    datetime.datetime.now(),
                    'read_error',
                    f'{type(e)}: {str(e)} | peername={repr(get_peername(writer))}',
                    None,
                    con_id,
                    None,
                    None,
                    None,
                )
                
                close()
                
                await asyncio.sleep(interval, loop=loop)
                
                continue
            
            date_now_dt = datetime.datetime.now()
            
            pkg_id = next(pkg_counter)
            client_id, server_pkg_id, date_nanos = struct.unpack('!QQQ', in_data)
            
            try:
                date_dt = nanos_to_dt(date_nanos)
            except OverflowError:
                date_dt = None
                lag_delta = None
            else:
                lag_delta = date_now_dt - date_dt
            
            log.write(
                False,
                datetime.datetime.now(),
                'received_pkg',
                f'peername={repr(get_peername(writer))}',
                lag_delta,
                con_id,
                client_id,
                pkg_id,
                server_pkg_id,
            )
    finally:
        log.write(
            False,
            datetime.datetime.now(),
            'client_shutdown',
            f'host={repr(host)} port={repr(port)} interval={repr(interval)}',
            None,
            None,
            None,
            None,
            None,
        )
        
        close()

def main():
    parser = argparse.ArgumentParser()
    
    parser.add_argument('--server', action='store_true')
    parser.add_argument('--log-prefix')
    parser.add_argument('--host')
    parser.add_argument('--port', type=int)
    parser.add_argument('--interval', type=float)
    
    args = parser.parse_args()
    
    if args.server:
        if args.host is None:
            raise UserError('missing host')
        
        if args.port is None:
            raise UserError('missing port')
    else:
        if args.log_prefix is None:
            raise UserError('missing log_prefix')
        
        if args.host is None:
            raise UserError('missing host')
        
        if args.port is None:
            raise UserError('missing port')
        
        if args.interval is None:
            raise UserError('missing interval')
    
    shutdown_event = asyncio.Event()
    
    def int_handler():
        shutdown_event.set()
    
    loop = asyncio.get_event_loop()
    
    loop.add_signal_handler(signal.SIGINT, int_handler)
    loop.add_signal_handler(signal.SIGTERM, int_handler)
    
    log = Log(args.log_prefix)
    
    if args.server:
        main_coro = server(loop, args.host, args.port)
    else:
        main_coro = client(
            loop,
            log,
            args.host,
            args.port,
            args.interval,
        )
    
    main_future = asyncio.ensure_future(main_coro, loop=loop)
    
    async def wait_shutdown():
        await shutdown_event.wait()
        
        main_future.cancel()
    
    wait_shutdown_future = asyncio.ensure_future(wait_shutdown(), loop=loop)
    
    try:
        loop.run_until_complete(main_future)
    except asyncio.CancelledError:
        pass
    
    log.shutdown()

if __name__ == '__main__':
    main()
