import matplotlib.pyplot as plt
from numpy import array

analy = [41.45567434861804, 14.217891366572765, 41.16230300150471, 23.206901436956088, 39.15576146353053, 21.15241633512492, 52.65084343074365, 18.976928952111102, 50.30387265383701, 17.186760921733608, 14.8230219069492]

trev = [0.920245399, 0.863911094, 0.927007299, 0.864150943, 0.760752688, 0.864512472, 0.832061069, 0.859950094, 0.809688581, 0.776397516, 0.87146283]

trev = list((x*100 for x in trev))

names = array(list(map(str, [83, 190, 81, 89, 15, 400, 23, 129, 90, 606, 191])))

data = list(zip(analy, trev, names))
data = sorted(data, key=lambda x: x[0], reverse=False)

xy = list(x[2] for x in data)
points = list(x[1] for x in data)

print(data)

plt.plot(xy, points)
plt.show()
