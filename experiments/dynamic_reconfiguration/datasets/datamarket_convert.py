firstline = 1
day = "2005-06-08"
sampledurationsecs = 300
scalingfactor = 1 #1000.0

with open("datamarket_orig.csv") as f:
    for line in f:
        if firstline == 1:
            firstline = 0
        else:
            fields = line.split(',')
            if len(fields) > 1 and day in fields[0]:
                ratebits = int(fields[1].strip())
                ratepktspersec = ((ratebits/8.0) / 1400.0) * scalingfactor
                print str(ratepktspersec) + " " + str(sampledurationsecs)

