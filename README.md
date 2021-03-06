# Secure Communications

This project is a Python project for dealing with file transfers using TCP / IP sockets.

## Motivation

This project was developed for the Information and Organizational Security course, at the Universidade de Aveiro. This code implements a client and a server using a proprietary protocol based on
in JSON messages, over TCP / IP sockets and explores concepts related to key exchange, symmetric ciphers and integrity control. It was developed using [python3](https://docs.python.org/3.0/).


## Usage
First tab:
```bash
cd Secure-Communications
source venv/bin/activate
python server.py
```
Second tab:
```bash
cd Secure-Communications
source venv/bin/activate
python client.py <file>
``` 

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## Authors
João Ferreira (jgmpof@gmail.com)  
João Magalhães (ricardo.magalhaes469@gmail.com)

## License
[MIT](https://choosealicense.com/licenses/mit/)
