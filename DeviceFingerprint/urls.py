from django.conf.urls import url, include
from django.urls import path
from . import views


urlpatterns= [
	path('packet/', views.receive_packet, name='receive_packet')
]