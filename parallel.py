import os
import Queue
import sys
import threading

__version__ = '1.0'
__author__ = 'Mike Leonhard <mike@restbackup.com>'

t_write_lock = threading.Lock()

def t_print(text):
    t_write(str(text) + os.linesep)

def t_write(text):
    global t_write_lock
    with t_write_lock:
        sys.stdout.write(str(text))
        sys.stdout.flush()

class QueueIterator:
    def __init__(self, queue):
        self.queue = queue
    def __iter__(self):
        return self
    def next(self):
        try:
            return self.queue.get(block=False)
        except Queue.Empty:
            raise StopIteration()

class IterableQueue (Queue.Queue):
    def __init__(self, maxsize=0):
        Queue.Queue.__init__(self, maxsize)
    def __iter__(self):
        return QueueIterator(self)

def process(func, items_in, num_threads=10):
    in_q = IterableQueue()
    out_q = IterableQueue()
    for item_in in items_in:
        in_q.put(item_in)
    def worker_thread():
        for item_in in in_q:
            item_out = func(item_in)
            out_q.put(item_out)
    threads = []
    for n in xrange(num_threads):
        thread = threading.Thread(target=worker_thread)
        thread.daemon = True
        thread.start()
        threads.append(thread)
    for thread in threads:
        thread.join()
    return [item_out for item_out in out_q]
