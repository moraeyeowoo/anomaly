from django.conf.urls import url, include
from django.urls import path
from . import views


urlpatterns= [
	path('packet/', views.receive_packet, name='receive_packet'),
	path('echo/', views.echo_packet, name='echo_packet'),
]