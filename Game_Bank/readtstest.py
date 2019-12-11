


log = [[0]*3 for i in range(10)]
print (log)


with open ("tstest.txt", "r") as f:
    line = f.readline()

    date = line.split(' ')[3].split(':')[-1]

    while line:

        t = int(list(line.split(' ')[0])[-1])
        d = line.split(' ')[3].split(':')[-1]
        r = line.split(' ')[-2]


        if date != d:
            a = open('result.txt', 'a+')
            a.write (date + '\n')
            for i in range(10):
                a.write(str(i) + ': ' + str(log[i][0]) + ' ' + str(log[i][1]) + ' ' + str(log[i][2]) + '\n')
            log = [[0]*3 for i in range(10)]
            date = d
            a.close

        if r == 'made':
            log[t][0] += 1
        elif r == 'payment':
            log[t][1] += 1
        elif r == 'quit':
            log[t][2] += 1
        

        print ('---------------')
        print (t)
        print (d)
        print (r)


        line = f.readline()


