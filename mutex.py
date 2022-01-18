import scapy.all as scapy
import Project_Mitm.arp_spoofer
import threading
import time
sem = threading.Semaphore()
connected_ip={}
threads_counter = 0
mutex = threading.Lock()


def scan():
    with mutex:
        print("2")
        time.sleep(0.04)

def check():
    mutex.acquire()
    print("1")
    mutex.release()
    print("22222")

def check_loop():
    while True:
        checking = threading.Thread(target=check,args=())
        checking.start()
        time.sleep(0.05)

def scan_loop():
    while True:
        checking = threading.Thread(target=scan,args=())
        checking.start()




if __name__ == '__main__':
    sem.release()
    print(sem==False)
    scan_looper = threading.Thread(target=scan_loop)
    scan_looper.start()
    check_looper = threading.Thread(target=check_loop)
    check_looper.start()