from django.urls import path
from . import views

urlpatterns = [
    path('health', views.health_check, name='health'),
    path('analyze-ticket', views.analyze_ticket_view, name='analyze_ticket'),
]