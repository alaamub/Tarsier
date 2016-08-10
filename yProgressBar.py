import sys
import threading

class yProgressBar(threading.Thread):
	def __init__(self):
		threading.Thread.__init__(self)
		self.event = threading.Event()
		self.kill_received = False
	def run(self):
		while not self.kill_received:
			event = self.event
			while not event.is_set():
				sys.stdout.write(".")
				sys.stdout.flush()
				event.wait(1) # pause for 1 second
	def stop(self):
		self.event.set()
