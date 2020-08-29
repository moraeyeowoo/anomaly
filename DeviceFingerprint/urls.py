from django.conf.urls import url, include
from django.urls import path
from . import views


urlpatterns= [
	path('packet/', views.receive_packet, name='receive_packet'),
	path('echo/', views.echo_packet, name='echo_packet'),
	path('devices/', views.DeviceList.as_view(),name='devices'),
	path('devices/<int:pk>/', views.DeviceDetail.as_view(), name='device_detail'),
	path('<int:pk>/savepcap/',views.save_packet, name='save_packet'),
	path('classification/panel/', views.ControlPanel.as_view()),
	path('classification/panel/<int:pk>/', views.DeviceDetailPanel.as_view()),
	path('anomaly/<int:pk>/', views.AnomalyDetail.as_view()),
	path('anomalypanel/',views.AnomalyPanel.as_view()),
	path('anomalypanel/detail/<int:pk>/',views.AnomalyDetailPanel.as_view()),
]