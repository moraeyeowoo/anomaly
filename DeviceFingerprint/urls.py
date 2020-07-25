from django.conf.urls import url, include
from django.urls import path
from . import views


urlpatterns= [
	path('packet/', views.receive_packet, name='receive_packet'),
	path('echo/', views.echo_packet, name='echo_packet'),
	path('devices/', views.get_devices,name='devices'),
	path('<int:pk>/savepcap/',views.save_packet, name='save_packet'),
	path('panel/', views.ControlPanel.as_view()),
	path('anomaly/<int:pk>/', views.AnomalyDetail.as_view())
]
