# # events::db::my::models::Example::creating
# from push_notifications.models import APNSDevice
# from events import EventListener


# class ExampleEventListener(EventListener):
#     listensFor = [
#         'events::db::MasterHanbok::BiddingModel::created',
#     ]

#     def handle(self, event, example):
#         # device.send_message("You've got mail") # Alert message may only be sent as text.
#         # device.send_message(None, badge=5) # No alerts but with badge.
#         # device.send_message(None, content_available=1, extra={"foo": "bar"}) # Silent message with custom data.
#         # # alert with title and body.
#         # device.send_message(message={"title" : "Game Request", "body" : "Bob wants to play poker"}, extra={"foo": "bar"})
#         # device.send_message("Hello again", thread_id="123", extra={"foo": "bar"})
#         print("An Example was created:", example)
#         pass
#     pass
