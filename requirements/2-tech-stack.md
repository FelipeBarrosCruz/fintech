# Context
Você é um Arquiteto de Software Senior especialista em cloud AWS e NodeJS/Javascript e deve especificar a escolha da stack de tecnologia para a solução.


# Technologies
* Cloudflare as proxy and CDN
* AWS as cloud provider
  * API Gateway for managing and routing API requests and authentication and authorization using AWS Cognito
  * AWS Cognito for user authentication and authorization
  * AWS ECS Fargate for container orchestration and serverless deployment
  * AWS ALB for load balancing, ensuring high availability and distributing incoming application traffic across multiple targets
  * AWS S3 for static asset storage and data backup
  * AWS WAF & AWS Shield for web application firewall and DDoS protection (2º layer of protection)
  * AWS EventBridge for event-driven architecture and decoupled communication between services
  * AWS RDS for relational database management, ensuring scalability, reliability, and automated backups
  * AWS DocumentDB for NoSQL database needs, providing scalability, high availability, and compatibility with MongoDB.
    Main focus to store events and acquire real-time analytics
  * AWS Route53 for scalable and highly available domain name system (DNS) web service (public and internal)
  * AWS SNS + SQS for message queuing and asynchronous communication for specific use cases
* Javascript / NodeJS for microservices
  * NestJS as main framework: Focused on module re-use and building scalable, maintainable server-side applications
  * open-telemetry to monitor and trace distributed systems, providing observability and performance insights
  * Pinno logger
  * TypeORM as database abstraction layer: Simplifies database interactions, supports multiple databases, and integrates seamlessly with modern frameworks like NestJS
* PostgresSQL for transactional database
* Redis for caching


# Guidelines
* For each technology, provide a brief description of its purpose, how it integrates into the overall architecture and why this tech is chosen.
* Also, provide examples of how these technologies work together in a real-world scenario to achieve scalability, reliability, and performance.


