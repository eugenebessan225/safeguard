import multiprocessing as mp

# Should probably be called somehting like packetQ

# capture --> detectors/services
global sharedQ
sharedQ = mp.Queue()

# detectors --> services
global serviceQ
serviceQ = mp.Queue()

# services --> counts/times
global timesQ
timesQ = mp.Queue()

global featuresQ
featuresQ = mp.Queue()

global predictQ
predictQ = mp.Queue()