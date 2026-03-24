import time


def measure_time(func, *args):
    start = time.time()
    result = func(*args)
    end = time.time()
    return result, round(end - start, 5)

