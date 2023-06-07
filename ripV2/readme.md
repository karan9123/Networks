# RIP Distance-Vector Routing Protocol
This project implements a distance-vector routing protocol called RIP (Routing Information Protocol). RIP enables routers in a network to exchange routing information with each other to compute the shortest paths from each router to all the other routers in the network.

## Network Topology
The network consists of four virtual routers. The four virtual routers are:

- queeg: 129.21.30.37
- comet: 129.21.34.80
- rhea: 129.21.37.49
- glados: 129.21.22.196

The subnet mask is 255.255.255.0, and each router communicates with its neighbors via UDP datagram sockets. The routers are connected in a ring topology, where each router is connected to two other neighbors in the order queeg – comet – rhea – glados – queeg. The cost of each link is given arbitrarily as user input.

## Steps to Run the Project
- Pull the Docker image for Kali Linux by running the following command:


```
docker pull karan9123/kalihost
```

- Create a directory for the project and name it "proj05".

- Place the docker-compose.yaml file in the proj05 directory.

- Change into the proj05 directory.

- Compose the Docker containers using the following command:

```
docker-compose up -d
```
- Run all containers bash by typing the following command for each server:

```
docker exec -it proj05-<SERVER-NAME>-1 bash
```

Replace **<SERVER-NAME>** with the name of the server, which can be **queeg, comet, rhea**, or **glados**.

- In the container, create a new __Go__ module using the following command:

```
go mod init ripV2
```

-Create a __ripV2.go__ file using the following command:
```
touch ripV2.go
```

- Update the code in the ripV2.go file with the implementation of the RIP protocol submitted.

- Run the program using the following command:

```
go run ripV2.go -n <SERVER-NAME> -lp <LOSS-PERCENTAGE> -if eth0
```

Replace **<SERVER-NAME>** with the name of the server, which can be **queeg, comet, rhea**, or **glados**. **<LOSS-PERCENTAGE>** is the percentage of package loss you want to introduce, and **-if** is the name of the interface of the system, which should be **eth0** for this container.




