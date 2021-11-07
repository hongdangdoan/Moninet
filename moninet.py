import module
import sys,getopt
import plugins.bruteforce as BRUTEFORCE

FILE_DATA_LIVE_MONITOR = "Moninet.csv"
def main():

    print("running")
    filePCAP = None
    fileCSV = None
    interface = None
    option = None
    argv = sys.argv[1:]
    monitor = False
    analyst = False
    checkFile = None
    try:
        opts, args = getopt.getopt(argv, "p:c:i:o:m:a")
      
    except:
        print("Error")
    for opt, arg in opts:
        if opt in ['-p']:
            filePCAP = arg
        elif opt in ['-c']:
            fileCSV = arg
        elif opt in ['-i']:
            interface = arg
        elif opt in ['-o']:
            option = arg
        elif opt in ['-m']:
            monitor = True
            checkFile = arg 
        elif opt in ['-a']:
            analyst = True
            


    if(option=='1'):
        module.showNetWorkConversation(filePCAP)
    if(option=='2'):
        module.writeToCSV(filePCAP, fileCSV)
    if(option=='3'):
       module.liveCapture(fileCSV, interface)
    if(option==None):
 
        if(analyst==True):
            BRUTEFORCE.ids(fileCSV)
  
        if(monitor==True):
            if(checkFile=='1'):
                module.liveMonitor(FILE_DATA_LIVE_MONITOR,interface)

    



    

if __name__ == "__main__":
    main()