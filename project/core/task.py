from celery import shared_task
from . models import *
from time import sleep


@shared_task
def sleepy(duration):
    sleep(duration)
    return None


@shared_task
def delete_rooms():
    Room.objects.all().delete()
    return None