import multiprocessing

class Sender(multiprocessing.Process):
    def __init__(self,inQ):
        multiprocessing.Process.__init__(self)
        self.inQ = inQ

    def run(self):
        while True:
            if not self.inQ.empty():
                theData = self.inQ.get()
                