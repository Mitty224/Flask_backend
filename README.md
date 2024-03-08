# Flask backend
this is backend on flask with python. this repo includes registration, api, authentication, jwt token, PostgreSQL database and etc.
# what about usage?
#### you can use it as a clue or tips. find smth interesting or look and say: 'oh shit it is awful'

so if you are still here there is some tips and installation for you
```shell
pip3 install Flask
pip3 install Werkzeug
pip3 install psycopg2-binary
pip3 install datetime
pip3 install pyjwt
```
and important part of database: database works if you export variables,
all of this is default options:
```shell
export POSTGRES_DATABASE='postgres'
export POSTGRES_USERNAME='postgres'
export POSTGRES_PASSWORD='your secret (no) password'
export POSTGRES_HOST='localhost'
export POSTGRES_PORT='5432'
```
(check my code idk)
# files 
there is 4 files with different databases.
i made a one-to-one connect using PostgreSQL.
Docker file only for environment and if you don\`t know how to use it, don\`t use it
what about app.py? - check the name of functions and comments


# future
may be i will fix bugs and upgrade this project

