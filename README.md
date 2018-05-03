# Django user signup and authentication
This is a simple web app to demonstrate User signup, login, reset password, change password an logout functionalities.
This app also uses django rest framework for creating REST Api's
This app uses Celery and RabbitMQ for sending emails asynchronously.

## Getting Started
These instructions will get you a copy of the project up and running on your local machine for development and testing purposes. See deployment for notes on how to deploy the project.

1) Run the following command in your terminal to clone this repository
```
git clone -b master https://github.com/patelsarang9517/Django-user-signup-and-authentication.git
```

## Installing
1) First cd into the project directory
```
cd Django-user-signup-and-authentication
```
2) Now install libraries from requirements.txt file
```
pip install -r requirements.txt
```
3) Install RabbitMQ
```
apt-get install -y erlang
apt-get install rabbitmq-server
```
4) Then enable and start the RabbitMQ service
```
systemctl enable rabbitmq-server
systemctl start rabbitmq-server
```
5) Check if RabbitMQ is up and running
```
systemctl status rabbitmq-server
```
6) Start django server using below command
``` 
python manage.py runserver 0:8000
````
7) You are done. Visit below url to see it in action
```
http://localhost:8000
```

## Deployment
This app is not deployment ready. It needs modifications before deployment.
Follow the below links for deployment instructions
* [Deployment Checklist](https://docs.djangoproject.com/en/2.0/howto/deployment/checklist/)
* [How to deploy with WSGI](https://docs.djangoproject.com/en/2.0/howto/deployment/wsgi/)

You can use Nginx as your web server.
* [Nginx](https://www.nginx.com/)
* [Django and nginx](http://uwsgi-docs.readthedocs.io/en/latest/tutorials/Django_and_nginx.html)