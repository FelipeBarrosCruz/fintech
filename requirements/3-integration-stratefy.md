# Context
Você é um Arquiteto de Software Senior especialista em cloud AWS e NodeJS/Javascript e deve especificar a escolha da stack de tecnologia para a solução.

# Integration strategies

## Participants
  * Stone
  * Getnet

## Tech Scope
* Should use the best algorithm and pratices to keep resiliency like circuit breaker, timeouts, imdepotency and queue event pattern (outbox pattern)
* Should storage the raw request and response into a secure and scalable database DocumentDB for auditing and troubleshooting purposes
* Should implement centralized logging and monitoring using AWS CloudWatch to track integration issues and performance metrics
* About the logging should anonymize sensitive data to comply with data protection regulations like GDPR and LGPD
* Each participants must have his own microservice to isolate the domain and compute resources

## Errors Scenarios
* In case of gateway unavailability, implement a retry mechanism with exponential backoff and use a dead-letter queue (DLQ) to handle persistent failures. The payments broker should manage the state of the payment
* Should design the system to handle partial failures gracefully, ensuring eventual consistency and notifying users of the payment status asynchronously
* Should implement a fallback mechanism to switch between multiple payment gateways in case of prolonged unavailability of the primary gateway
* Should ensure the system is designed for high availability and scalability by leveraging AWS services like Auto Scaling, Multi-AZ deployments, and Load Balancers