Wikiverse is an astronomical visualization platform designed to explore SPHEREx observations, compare celestial objects over time and identify potential astronomical anomalies.

Architecture



Technologies & Components

Component

Role

Amazon EC2

Hosts the Wikiverse web application.

FastAPI

Python backend responsible for API requests, application logic and communication with external services.

Amazon S3

Stores astronomical images uploaded from SphereX.

AWS Lambda

Processes S3 upload events and triggers notifications.

Amazon SNS

Sends notifications to subscribed users.

SQLite

Current database used for application data and user information.

AstroQuery

Python astronomy package used for astronomical data access and analysis.

NASA/IPAC IRSA

External astronomical archive providing access to scientific datasets and SPHEREx products.

SphereX

External source of astronomical images.

How It Works

1. Web Application

Users access Wikiverse through the frontend hosted on Amazon EC2.

The frontend communicates bidirectionally with the FastAPI backend over HTTP. FastAPI processes requests and exchanges information with AstroQuery, SQLite and NASA/IPAC IRSA.

2. Image Upload & Notifications

The image management workflow follows this sequence:

SphereX uploads astronomical images directly to Amazon S3.

S3 generates an object creation event.

AWS Lambda receives the event and executes the corresponding processing logic.

Lambda triggers Amazon SNS.

SNS distributes notifications to subscribed users.

3. External Data Integration

FastAPI acts as the central communication layer between the application and external astronomical resources.

AstroQuery: Provides astronomical data access and analysis capabilities.

NASA/IPAC IRSA: Provides access to astronomical observation data and original SPHEREx products.

SQLite: Handles the current application database operations.

Architecture Notes

The architecture combines AWS cloud services with external scientific tools and data sources.

The reviewed backend currently uses SQLite and local image storage. Amazon S3, Lambda and SNS represent the planned cloud-based image storage and notification workflow.
