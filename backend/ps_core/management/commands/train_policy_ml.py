from django.core.management.base import BaseCommand
from ps_core.ml.train import train_model

class Command(BaseCommand):
    help = 'Train the policy paragraph ML model'

    def handle(self, *args, **options):
        self.stdout.write("Starting ML training...")
        train_model()
        self.stdout.write(self.style.SUCCESS('Training complete.'))
