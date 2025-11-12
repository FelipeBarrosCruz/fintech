# Diagramas de Arquitetura - Plataforma de Pagamentos

## 1. Visão Geral da Arquitetura

```mermaid
graph TB
    subgraph "Edge Layer"
        CF[Cloudflare<br/>CDN, WAF, DDoS]
    end
    
    subgraph "AWS Cloud"
        subgraph "API Layer"
            APIGW[API Gateway]
            COGNITO[AWS Cognito<br/>Authentication]
            ALB[Application Load Balancer]
        end
        
        subgraph "Microservices - ECS Fargate"
            USER[User Service<br/>Gestão de Usuários]
            PAYMENT[Payments Service<br/>Orquestração de Pagamentos]
            STORE[Store Service<br/>Roteamento Inteligente]
            GETNET[Getnet Service<br/>Integração Gateway]
            NOTIF[Notification Service<br/>Multi-canal]
            FRAUD[Anti-Fraud Service<br/>Orquestração Fraude]
            CLEAR[Anti-Fraud Clearsale<br/>Integração Clearsale]
            KOND[Anti-Fraud Konduto<br/>Integração Konduto]
            LEDGER[Ledger Service<br/>Contabilidade]
        end
        
        subgraph "Data Layer"
            RDS[(RDS PostgreSQL<br/>Transactional Data)]
            DOCDB[(DocumentDB<br/>Events & Audit)]
            REDIS[(Redis<br/>Cache & Sessions)]
            S3[(S3<br/>Storage)]
        end
        
        subgraph "Event Layer"
            EB[EventBridge<br/>Event Bus]
            SNS[SNS]
            SQS[SQS]
        end
    end
    
    subgraph "External Services"
        GETNET_API[Getnet API]
        CLEAR_API[Clearsale API]
        KOND_API[Konduto API]
        SES[AWS SES<br/>Email]
    end
    
    subgraph "Observability"
        DD[Datadog]
        CW[CloudWatch]
        OTEL[OpenTelemetry]
    end
    
    %% Edge to AWS
    CF --> APIGW
    
    %% API Layer
    APIGW --> COGNITO
    COGNITO --> ALB
    ALB --> USER
    ALB --> PAYMENT
    ALB --> STORE
    ALB --> NOTIF
    ALB --> FRAUD
    ALB --> LEDGER
    
    %% Service Communications
    PAYMENT --> STORE
    PAYMENT --> USER
    STORE --> GETNET
    GETNET --> GETNET_API
    
    %% Fraud Flow
    PAYMENT --> FRAUD
    FRAUD --> CLEAR
    FRAUD --> KOND
    CLEAR --> CLEAR_API
    KOND --> KOND_API
    CLEAR --> FRAUD
    KOND --> FRAUD
    FRAUD --> USER
    
    %% Event Flow
    PAYMENT --> EB
    USER --> EB
    GETNET --> EB
    FRAUD --> EB
    EB --> SNS
    SNS --> SQS
    SQS --> LEDGER
    SQS --> NOTIF
    
    %% Data Access
    USER --> RDS
    PAYMENT --> RDS
    LEDGER --> RDS
    FRAUD --> RDS
    
    GETNET --> DOCDB
    LEDGER --> DOCDB
    FRAUD --> DOCDB
    CLEAR --> DOCDB
    KOND --> DOCDB
    
    PAYMENT --> REDIS
    STORE --> REDIS
    NOTIF --> REDIS
    FRAUD --> REDIS
    KOND --> REDIS
    
    USER --> S3
    LEDGER --> S3
    
    %% Notifications
    NOTIF --> SES
    NOTIF --> SNS
    
    %% Observability
    USER -.-> DD
    PAYMENT -.-> DD
    STORE -.-> DD
    GETNET -.-> DD
    NOTIF -.-> DD
    FRAUD -.-> DD
    CLEAR -.-> DD
    KOND -.-> DD
    LEDGER -.-> DD
    
    USER -.-> CW
    PAYMENT -.-> CW
    STORE -.-> CW
    GETNET -.-> CW
    NOTIF -.-> CW
    FRAUD -.-> CW
    CLEAR -.-> CW
    KOND -.-> CW
    LEDGER -.-> CW
    
    style CF fill:#f96,stroke:#333,stroke-width:2px
    style APIGW fill:#ff9,stroke:#333,stroke-width:2px
    style PAYMENT fill:#9cf,stroke:#333,stroke-width:2px
    style FRAUD fill:#f9c,stroke:#333,stroke-width:2px
    style LEDGER fill:#9f9,stroke:#333,stroke-width:2px
```

## Referências

- **Documentação de Cenários**: `docs/0-scenarios.md`
- **Mapeamento de Serviços**: `docs/1-service-map.md`
- **Stack Tecnológica**: `docs/2-tech-stack.md`
- **Estratégia de Integração**: `docs/3-integration-stratefy.md`
- **Segurança**: `docs/4-security.md`
- **Observabilidade**: `docs/5-observability.md`
- **Plano de Evolução**: `docs/8-evolution.md`
