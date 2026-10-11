"""Additional real-driver checks used by the fresh protected ORM runner."""

from datetime import date, datetime, timedelta, timezone
from decimal import Decimal
import threading
import time
from uuid import UUID

import psycopg
from psycopg.types.json import Jsonb
from psycopg.types.numeric import Float4, Float8, Int2, Int4, Int8


def check_values(connection):
    """Assert driver-decoded values and PostgreSQL OIDs, not formatted strings."""
    connection.execute('CREATE TABLE driver_types ('
        'id BIGINT PRIMARY KEY, flag BOOLEAN, small SMALLINT, medium INTEGER, big BIGINT, '
        'real_value REAL, double_value DOUBLE PRECISION, amount DECIMAL(20,4), '
        'label VARCHAR(32), body TEXT, bytes_value BYTEA, day DATE, moment TIMESTAMPTZ, '
        'token UUID, document JSONB)')
    stamp = datetime(1999, 12, 31, 23, 59, 59, 123456,
                     tzinfo=timezone(timedelta(hours=7)))
    token = UUID('ffeeddcc-bbaa-9988-7766-554433221100')
    document = {'nested': [None, True, 42, 'Kopi ☕'], 'empty': {}}
    values = (True, Int2(-32768), Int4(-2147483648), Int8(9223372036854775807),
              Float4(1.25), Float8(-0.125), Decimal('-123456789012.3456'),
              'Kopi ☕', "quotes ' and \\ slash", b'\x00\x01\xff\x00',
              date(1999, 12, 31), stamp, token, Jsonb(document))
    expected = values[:-1] + (document,)
    oids = [20, 16, 21, 23, 20, 700, 701, 1700, 1043, 25, 17, 1082, 1184, 2950, 3802]
    for row_id, format_code in [(1, '%t'), (2, '%b')]:
        # NUMERIC text input is currently supported; its binary output is checked.
        placeholders = [format_code] * len(values)
        placeholders[6] = '%t'
        sql = 'INSERT INTO driver_types VALUES (%b,' + ','.join(placeholders) + ')'
        connection.execute(sql, (Int8(row_id),) + values, prepare=True)
        for binary in [False, True]:
            cursor = connection.execute('SELECT * FROM driver_types WHERE id=%b',
                                        (Int8(row_id),), binary=binary, prepare=True)
            assert [column.type_code for column in cursor.description] == oids
            assert cursor.fetchone() == (row_id,) + expected
    connection.execute('INSERT INTO driver_types (id) VALUES (3)')
    assert connection.execute('SELECT * FROM driver_types WHERE id=3', binary=True).fetchone() == (3,) + (None,) * 14
    # An unsupported input encoding must be rejected before any durable mutation.
    try:
        connection.execute('INSERT INTO driver_types (id,amount) VALUES (4,%b)',
                           (Decimal('1.2500'),), prepare=True)
    except psycopg.Error as error:
        assert error.sqlstate == '0A000', error.sqlstate
    else:
        raise AssertionError('update the NUMERIC binary contract and test when supported')
    assert connection.execute('SELECT COUNT(*) FROM driver_types').fetchone() == (3,)
    return {'roundtrips': 4, 'columns': 15, 'null_roundtrip': True,
            'numeric_binary_input': '0A000_before_mutation'}


def check_cancellation(connection):
    """Cancel real in-flight work via libpq, then verify transaction recovery."""
    connection.execute('CREATE TABLE driver_cancel (id BIGINT PRIMARY KEY, body TEXT)')
    # A valid large INSERT gives the driver time to cancel during parsing or
    # execution without relying on test-only server failpoints or pg_sleep.
    sql = 'INSERT INTO driver_cancel VALUES ' + ','.join(
        f"({index},'cancel payload')" for index in range(20000))
    connection.execute('BEGIN')
    connection.execute(sql)
    assert connection.execute('SELECT COUNT(*) FROM driver_cancel').fetchone() == (20000,)
    connection.execute('ROLLBACK')
    outcomes = []
    for in_transaction, prepared in [(True, False), (True, True), (False, True)]:
        if in_transaction:
            connection.execute('BEGIN')
        finished = threading.Event()
        outcome = {}

        def execute():
            try:
                connection.execute(sql, prepare=prepared)
                outcome['sqlstate'] = 'unexpected_success'
            except psycopg.Error as error:
                outcome['sqlstate'] = error.sqlstate
            finally:
                finished.set()

        worker = threading.Thread(target=execute, daemon=True)
        started = time.monotonic()
        cancel_requests = 0
        worker.start()
        try:
            while not finished.wait(0.002):
                connection.cancel_safe(timeout=2)
                cancel_requests += 1
                if time.monotonic() - started > 10:
                    raise AssertionError('query did not finish after cancellation')
        finally:
            worker.join(timeout=3)
        assert not worker.is_alive(), 'cancelled query worker leaked'
        assert outcome['sqlstate'] == '57014', {
            **outcome, 'prepared': prepared, 'cancel_requests': cancel_requests,
            'in_transaction': in_transaction,
            'elapsed_seconds': time.monotonic() - started, 'previous_attempts': outcomes}
        if in_transaction:
            try:
                connection.execute('SELECT COUNT(*) FROM driver_cancel')
            except psycopg.Error as error:
                assert error.sqlstate == '25P02', error.sqlstate
            else:
                raise AssertionError('cancelled transaction must require rollback')
            connection.execute('ROLLBACK')
        assert connection.execute('SELECT COUNT(*) FROM driver_cancel').fetchone() == (0,)
        outcomes.append({'sqlstate': outcome['sqlstate'],
                         'prepared': prepared,
                         'in_transaction': in_transaction,
                         'cancel_requests': cancel_requests,
                         'elapsed_seconds': round(time.monotonic() - started, 6)})
    connection.cancel_safe(timeout=2)
    connection.execute("INSERT INTO driver_cancel VALUES (1,'after cancellation')")
    assert connection.execute('SELECT COUNT(*) FROM driver_cancel').fetchone() == (1,)
    return {'valid_control_rows': 20000, 'attempts': outcomes, 'idle_cancel': 'next_write_pass',
            'rollback': 'zero_partial_rows'}
