from django.test import TestCase

# Create your tests here.
from rest_framework.test import APITestCase
from rest_framework import status
from django.urls import reverse
from .models import Ticket
from rest_framework.test import APIClient



class TicketAPITests(APITestCase):
    
    def setUp(self):
        self.ticket = Ticket.objects.create(
            title="Sample Ticket",
            description="This is a sample ticket description."
        )
        self.client = APIClient()
        
    def test_get_ticket_list(self):
        url = reverse('ticket-list')
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreater(len(response.data), 0)
        
    def test_create_ticket(self):
        url = reverse('ticket-list')
        data = {
            'title': 'New Ticket',
            'description': 'A description for the new ticket.'
        }
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['title'], data['title'])
        self.assertEqual(response.data['description'], data['description'])

    def test_get_ticket_detail(self):
        url = reverse('ticket-detail', kwargs={'pk': self.ticket.pk})
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['title'], self.ticket.title)
        self.assertEqual(response.data['description'], self.ticket.description)

    def test_update_ticket(self):
        url = reverse('ticket-detail', kwargs={'pk': self.ticket.pk})
        data = {
            'title': 'Updated Ticket',
            'description': 'Updated description.'
        }
        response = self.client.put(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['title'], data['title'])
        self.assertEqual(response.data['description'], data['description'])

    def test_delete_ticket(self):
        url = reverse('ticket-detail', kwargs={'pk': self.ticket.pk})
        response = self.client.delete(url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        with self.assertRaises(Ticket.DoesNotExist):
            Ticket.objects.get(pk=self.ticket.pk)

    def test_create_ticket_invalid(self):
        url = reverse('ticket-list')
        data = {
            'title': '',
            'description': ''
        }
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('title', response.data)
        self.assertIn('description', response.data)
