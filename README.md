# Scc-DemoApplication
This is a guide on how to setup and run the demo3 application utilizing the GD library.

On the raspberry pi, move to the following directory:
```
/home/pi/Downloads/demo/scc-lib/demo-src
```

## Compile the demo3.cpp file
![alt text](images/3compile.png)
enter the .../scc-lib/demo-src folder and issue the following command:

```
g++ demo3.cpp -lscc-toolkit -lssl -lcrypto -o demo3 -std=c++17

```
this generates the demo3 executable which can be run via the command: 

```
./demo3
```

## Optional
If  Download the scc-lib.zip from workspaces (watchdocs)
![alt text](images/1Downloadzip.png)

Unzip and move the folder to the Raspberry pi
![alt text](images/2movefilesover.png)
