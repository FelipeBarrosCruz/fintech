# Documentação: Observabilidade e Monitoramento da Plataforma de Pagamentos

## 1. Visão Geral

Este documento detalha a estratégia completa de observabilidade da plataforma de pagamentos, incluindo logging, métricas, tracing distribuído, alertas, estratégias de deploy e disaster recovery. O objetivo é garantir visibilidade total do sistema, detecção proativa de problemas e resposta rápida a incidentes.

## 2. Pilares da Observabilidade

### 2.1 Os Três Pilares
```
┌─────────────────────────────────────────────────────────┐
│                    OBSERVABILITY                         │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐ │
│  │   LOGGING    │  │   METRICS    │  │   TRACING    │ │
│  │              │  │              │  │              │ │
│  │ • Structured │  │ • Business   │  │ • Distributed│ │
│  │ • Centralized│  │ • Technical  │  │ • End-to-end │ │
│  │ • Searchable │  │ • Real-time  │  │ • Latency    │ │
│  │ • Contextual │  │ • Historical │  │ • Dependencies│ │
│  └──────────────┘  └──────────────┘  └──────────────┘ │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

### 2.2 Stack de Observabilidade
- **Datadog**: Plataforma principal (APM, Logs, Metrics)
- **CloudWatch**: Logs e métricas AWS nativas
- **OpenTelemetry**: Instrumentação padronizada
- **Pino**: Logging estruturado em NodeJS

## 3. Logging

### 3.1 Datadog Log Management

#### 3.1.1 Propósito
- Centralização de logs de todos os serviços
- Busca e análise em tempo real
- Correlação com traces e métricas
- Alertas baseados em logs
- Retenção configurável

#### 3.1.2 Arquitetura de Logging
```
┌──────────────────┐
│  Microservices   │
│  (Pino Logger)   │
└────────┬─────────┘
         │ JSON logs
         ↓
┌──────────────────┐
│  CloudWatch      │
│  Logs            │
└────────┬─────────┘
         │ Stream
         ↓
┌──────────────────┐
│  Datadog Agent   │
│  (Forwarder)     │
└────────┬─────────┘
         │ Enriched logs
         ↓
┌──────────────────┐
│  Datadog         │
│  Log Management  │
└──────────────────┘
```

#### 3.1.3 Estrutura de Log Padronizada
```typescript
// logger.config.ts
import pino from 'pino';

export const logger = pino({
  level: process.env.LOG_LEVEL || 'info',
  formatters: {
    level: (label) => ({ level: label }),
    bindings: (bindings) => ({
      pid: bindings.pid,
      hostname: bindings.hostname,
      service: process.env.SERVICE_NAME,
      environment: process.env.NODE_ENV,
      version: process.env.APP_VERSION
    })
  },
  redact: {
    paths: [
      'req.headers.authorization',
      'req.body.password',
      'req.body.cardNumber',
      'req.body.cvv',
      'res.body.token'
    ],
    remove: true
  },
  serializers: {
    req: (req) => ({
      method: req.method,
      url: req.url,
      headers: {
        host: req.headers.host,
        'user-agent': req.headers['user-agent'],
        'content-type': req.headers['content-type']
      },
      remoteAddress: req.remoteAddress,
      remotePort: req.remotePort
    }),
    res: (res) => ({
      statusCode: res.statusCode,
      headers: {
        'content-type': res.headers['content-type']
      }
    }),
    err: pino.stdSerializers.err
  }
});

// Exemplo de log estruturado
logger.info({
  action: 'payment.created',
  paymentId: 'uuid-123',
  userId: 'uuid-456',
  amount: 100.00,
  currency: 'BRL',
  gateway: 'getnet',
  duration: 850,
  success: true,
  trace_id: 'trace-abc',
  span_id: 'span-xyz'
}, 'Payment created successfully');
```

#### 3.1.4 Níveis de Log
```typescript
// ERROR: Erros que requerem atenção imediata
logger.error({
  action: 'payment.failed',
  paymentId: 'uuid-123',
  error: error.message,
  stack: error.stack
}, 'Payment processing failed');

// WARN: Situações anormais mas não críticas
logger.warn({
  action: 'gateway.slow_response',
  gateway: 'getnet',
  duration: 5000,
  threshold: 3000
}, 'Gateway response time exceeded threshold');

// INFO: Eventos importantes do negócio
logger.info({
  action: 'user.created',
  userId: 'uuid-123',
  userType: 'customer'
}, 'New user registered');

// DEBUG: Informações detalhadas para debugging
logger.debug({
  action: 'cache.hit',
  key: 'payment:uuid-123',
  ttl: 300
}, 'Cache hit');
```

#### 3.1.5 Contexto de Requisição
```typescript
// request-context.middleware.ts
import { v4 as uuidv4 } from 'uuid';
import { AsyncLocalStorage } from 'async_hooks';

const asyncLocalStorage = new AsyncLocalStorage();

@Injectable()
export class RequestContextMiddleware implements NestMiddleware {
  use(req: Request, res: Response, next: NextFunction) {
    const requestId = req.headers['x-request-id'] || uuidv4();
    const traceId = req.headers['x-trace-id'] || uuidv4();
    
    const context = {
      requestId,
      traceId,
      userId: req.user?.id,
      ip: req.ip,
      userAgent: req.headers['user-agent']
    };
    
    asyncLocalStorage.run(context, () => {
      res.setHeader('X-Request-ID', requestId);
      res.setHeader('X-Trace-ID', traceId);
      next();
    });
  }
}

// logger.service.ts
@Injectable()
export class LoggerService {
  private getContext() {
    return asyncLocalStorage.getStore() || {};
  }
  
  info(obj: any, msg?: string) {
    logger.info({ ...this.getContext(), ...obj }, msg);
  }
  
  error(obj: any, msg?: string) {
    logger.error({ ...this.getContext(), ...obj }, msg);
  }
}
```

#### 3.1.6 Datadog Log Queries
```
# Buscar erros de pagamento nas últimas 24h
service:payments-service status:error action:payment.* @duration:>3000

# Buscar logs de um usuário específico
@userId:uuid-123

# Buscar logs de uma transação completa
@trace_id:trace-abc

# Buscar gateways lentos
service:getnet-service @duration:>3000

# Buscar erros 5xx
@http.status_code:[500 TO 599]
```

---

### 3.2 CloudWatch Logs

#### 3.2.1 Propósito
- Logs nativos de serviços AWS
- Backup de logs
- Integração com Lambda
- Métricas derivadas de logs

#### 3.2.2 Log Groups
```yaml
LogGroups:
  - Name: /ecs/payments-service
    RetentionDays: 30
    
  - Name: /ecs/user-service
    RetentionDays: 30
    
  - Name: /ecs/getnet-service
    RetentionDays: 90  # Maior retenção para auditoria
    
  - Name: /aws/lambda/outbox-processor
    RetentionDays: 14
    
  - Name: /aws/apigateway/payments-api
    RetentionDays: 30
```

#### 3.2.3 Metric Filters
```yaml
MetricFilters:
  - FilterName: PaymentErrors
    FilterPattern: '[time, request_id, level = ERROR, action = payment.*]'
    MetricTransformation:
      MetricName: PaymentErrorCount
      MetricNamespace: PaymentsPlatform
      MetricValue: 1
  
  - FilterName: SlowPayments
    FilterPattern: '[time, request_id, level, action = payment.*, duration > 3000]'
    MetricTransformation:
      MetricName: SlowPaymentCount
      MetricNamespace: PaymentsPlatform
      MetricValue: 1
```

---

## 4. Métricas

### 4.1 Datadog APM (Application Performance Monitoring)

#### 4.1.1 Propósito
- Monitoramento de performance de aplicações
- Detecção de bottlenecks
- Análise de dependências
- Profiling de código

#### 4.1.2 Métricas de Negócio
```typescript
// datadog-metrics.service.ts
import { StatsD } from 'hot-shots';

@Injectable()
export class DatadogMetricsService {
  private statsd: StatsD;
  
  constructor() {
    this.statsd = new StatsD({
      host: process.env.DD_AGENT_HOST || 'localhost',
      port: 8125,
      prefix: 'payments_platform.',
      globalTags: {
        env: process.env.NODE_ENV,
        service: process.env.SERVICE_NAME,
        version: process.env.APP_VERSION
      }
    });
  }
  
  // Counter: Incrementa valor
  incrementPaymentCreated(gateway: string) {
    this.statsd.increment('payment.created', 1, {
      gateway
    });
  }
  
  // Gauge: Valor atual
  setActiveUsers(count: number) {
    this.statsd.gauge('users.active', count);
  }
  
  // Histogram: Distribuição de valores
  recordPaymentAmount(amount: number, currency: string) {
    this.statsd.histogram('payment.amount', amount, {
      currency
    });
  }
  
  // Timing: Duração de operações
  recordPaymentDuration(duration: number, gateway: string, success: boolean) {
    this.statsd.timing('payment.duration', duration, {
      gateway,
      success: success.toString()
    });
  }
  
  // Distribution: Percentis
  recordAPILatency(latency: number, endpoint: string) {
    this.statsd.distribution('api.latency', latency, {
      endpoint
    });
  }
}

// Usage
@Injectable()
export class PaymentsService {
  constructor(private readonly metrics: DatadogMetricsService) {}
  
  async createPayment(dto: CreatePaymentDto): Promise<Payment> {
    const startTime = Date.now();
    
    try {
      const payment = await this.processPayment(dto);
      
      const duration = Date.now() - startTime;
      
      // Registrar métricas
      this.metrics.incrementPaymentCreated(payment.gateway);
      this.metrics.recordPaymentAmount(payment.amount, payment.currency);
      this.metrics.recordPaymentDuration(duration, payment.gateway, true);
      
      return payment;
      
    } catch (error) {
      const duration = Date.now() - startTime;
      this.metrics.recordPaymentDuration(duration, dto.gateway, false);
      throw error;
    }
  }
}
```

#### 4.1.3 Métricas Técnicas
```typescript
// Custom metrics
export class MetricsCollector {
  // Database connection pool
  recordDBPoolSize(size: number, available: number) {
    this.statsd.gauge('db.pool.size', size);
    this.statsd.gauge('db.pool.available', available);
  }
  
  // Cache hit rate
  recordCacheHit(hit: boolean) {
    this.statsd.increment(`cache.${hit ? 'hit' : 'miss'}`);
  }
  
  // Queue depth
  recordQueueDepth(queue: string, depth: number) {
    this.statsd.gauge('queue.depth', depth, { queue });
  }
  
  // Circuit breaker state
  recordCircuitBreakerState(gateway: string, state: string) {
    this.statsd.gauge('circuit_breaker.state', 
      state === 'open' ? 1 : 0, 
      { gateway }
    );
  }
}
```

#### 4.1.4 Dashboards Datadog
```yaml
Dashboards:
  - Name: Payments Overview
    Widgets:
      - Type: timeseries
        Title: Payments per Minute
        Metric: payments_platform.payment.created
        Aggregation: sum
        GroupBy: gateway
      
      - Type: query_value
        Title: Success Rate
        Query: |
          (sum:payments_platform.payment.created{success:true} / 
           sum:payments_platform.payment.created{*}) * 100
      
      - Type: heatmap
        Title: Payment Duration Distribution
        Metric: payments_platform.payment.duration
        GroupBy: gateway
      
      - Type: toplist
        Title: Top Errors
        Metric: payments_platform.error.count
        GroupBy: error_type
        Limit: 10
  
  - Name: Infrastructure Health
    Widgets:
      - Type: timeseries
        Title: CPU Usage
        Metric: aws.ecs.service.cpuutilization
        GroupBy: service_name
      
      - Type: timeseries
        Title: Memory Usage
        Metric: aws.ecs.service.memory_utilization
        GroupBy: service_name
      
      - Type: query_value
        Title: Running Tasks
        Metric: aws.ecs.service.running
        Aggregation: avg
```

---

### 4.2 CloudWatch Metrics

#### 4.2.1 Métricas AWS Nativas
```yaml
CloudWatch_Metrics:
  ECS:
    - CPUUtilization
    - MemoryUtilization
    - RunningTaskCount
    - DesiredTaskCount
  
  ALB:
    - RequestCount
    - TargetResponseTime
    - HTTPCode_Target_2XX_Count
    - HTTPCode_Target_4XX_Count
    - HTTPCode_Target_5XX_Count
    - UnHealthyHostCount
  
  RDS:
    - CPUUtilization
    - DatabaseConnections
    - FreeableMemory
    - ReadLatency
    - WriteLatency
    - DiskQueueDepth
  
  API_Gateway:
    - Count (requests)
    - Latency
    - 4XXError
    - 5XXError
```

---

## 5. Distributed Tracing

### 5.1 OpenTelemetry

#### 5.1.1 Propósito
- Rastreamento end-to-end de requisições
- Visualização de dependências entre serviços
- Identificação de bottlenecks
- Análise de latência

#### 5.1.2 Configuração
```typescript
// tracing.ts
import { NodeSDK } from '@opentelemetry/sdk-node';
import { getNodeAutoInstrumentations } from '@opentelemetry/auto-instrumentations-node';
import { DatadogExporter } from '@opentelemetry/exporter-datadog';
import { Resource } from '@opentelemetry/resources';
import { SemanticResourceAttributes } from '@opentelemetry/semantic-conventions';

const sdk = new NodeSDK({
  resource: new Resource({
    [SemanticResourceAttributes.SERVICE_NAME]: process.env.SERVICE_NAME,
    [SemanticResourceAttributes.SERVICE_VERSION]: process.env.APP_VERSION,
    [SemanticResourceAttributes.DEPLOYMENT_ENVIRONMENT]: process.env.NODE_ENV
  }),
  traceExporter: new DatadogExporter({
    serviceName: process.env.SERVICE_NAME,
    agentUrl: process.env.DD_AGENT_URL || 'http://localhost:8126',
    tags: {
      env: process.env.NODE_ENV,
      version: process.env.APP_VERSION
    }
  }),
  instrumentations: [
    getNodeAutoInstrumentations({
      '@opentelemetry/instrumentation-http': {
        enabled: true,
        ignoreIncomingPaths: ['/health', '/metrics']
      },
      '@opentelemetry/instrumentation-express': {
        enabled: true
      },
      '@opentelemetry/instrumentation-pg': {
        enabled: true,
        enhancedDatabaseReporting: true
      },
      '@opentelemetry/instrumentation-redis': {
        enabled: true
      },
      '@opentelemetry/instrumentation-aws-sdk': {
        enabled: true
      }
    })
  ]
});

sdk.start();

process.on('SIGTERM', () => {
  sdk.shutdown()
    .then(() => console.log('Tracing terminated'))
    .catch((error) => console.log('Error terminating tracing', error))
    .finally(() => process.exit(0));
});
```

#### 5.1.3 Custom Spans
```typescript
import { trace, SpanStatusCode } from '@opentelemetry/api';

@Injectable()
export class PaymentsService {
  private tracer = trace.getTracer('payments-service');
  
  async createPayment(dto: CreatePaymentDto): Promise<Payment> {
    const span = this.tracer.startSpan('payment.create');
    
    span.setAttributes({
      'payment.amount': dto.amount,
      'payment.currency': dto.currency,
      'payment.gateway': dto.gateway,
      'user.id': dto.userId
    });
    
    try {
      // Validação
      const validationSpan = this.tracer.startSpan('payment.validate', {
        parent: span
      });
      await this.validatePayment(dto);
      validationSpan.end();
      
      // Processamento
      const processingSpan = this.tracer.startSpan('payment.process', {
        parent: span
      });
      const payment = await this.processPayment(dto);
      processingSpan.setAttributes({
        'payment.id': payment.id,
        'payment.status': payment.status
      });
      processingSpan.end();
      
      span.setStatus({ code: SpanStatusCode.OK });
      return payment;
      
    } catch (error) {
      span.setStatus({
        code: SpanStatusCode.ERROR,
        message: error.message
      });
      span.recordException(error);
      throw error;
      
    } finally {
      span.end();
    }
  }
}
```

#### 5.1.4 Trace Visualization
```
Trace: payment.create (850ms)
├─ payment.validate (50ms)
│  ├─ db.query: SELECT user (20ms)
│  └─ cache.get: user_limits (5ms)
├─ payment.process (750ms)
│  ├─ store.select_gateway (30ms)
│  │  └─ redis.get: routing_rules (5ms)
│  ├─ getnet.authorize (650ms)
│  │  ├─ http.post: /v1/payments/authorize (600ms)
│  │  └─ db.insert: gateway_audit (20ms)
│  └─ db.insert: payment (40ms)
└─ event.publish: payment.created (20ms)
```

---

## 6. Alertas e Monitoramento

### 6.1 Datadog Monitors

#### 6.1.1 Alertas de Negócio
```yaml
Monitors:
  - Name: High Payment Error Rate
    Type: metric alert
    Query: |
      sum(last_5m):
        sum:payments_platform.payment.created{success:false}.as_count() /
        sum:payments_platform.payment.created{*}.as_count() * 100 > 5
    Message: |
      Payment error rate is {{value}}% (threshold: 5%)
      
      Possible causes:
      - Gateway unavailability
      - Invalid payment data
      - Fraud detection
      
      @pagerduty-payments @slack-alerts
    Tags:
      - service:payments
      - severity:critical
    Thresholds:
      critical: 5
      warning: 3
  
  - Name: Low Payment Success Rate
    Type: metric alert
    Query: |
      avg(last_15m):
        sum:payments_platform.payment.created{success:true}.as_count() < 100
    Message: |
      Payment volume is unusually low: {{value}} payments/15min
      
      Expected: >100 payments/15min
      
      @slack-alerts
    Thresholds:
      critical: 50
      warning: 100
  
  - Name: High Payment Latency
    Type: metric alert
    Query: |
      avg(last_10m):
        avg:payments_platform.payment.duration{*} > 3000
    Message: |
      Payment processing is slow: {{value}}ms (threshold: 3000ms)
      
      Check:
      - Gateway performance
      - Database performance
      - Network issues
      
      @slack-alerts
    Thresholds:
      critical: 5000
      warning: 3000
```

#### 6.1.2 Alertas Técnicos
```yaml
Monitors:
  - Name: High CPU Usage
    Type: metric alert
    Query: |
      avg(last_5m):
        avg:aws.ecs.service.cpuutilization{service:payments-service} > 80
    Message: |
      CPU usage is high: {{value}}%
      
      Service: {{service.name}}
      
      @slack-devops
    Thresholds:
      critical: 90
      warning: 80
  
  - Name: High Memory Usage
    Type: metric alert
    Query: |
      avg(last_5m):
        avg:aws.ecs.service.memory_utilization{service:payments-service} > 85
    Message: |
      Memory usage is high: {{value}}%
      
      Possible memory leak or high load
      
      @slack-devops
    Thresholds:
      critical: 90
      warning: 85
  
  - Name: Database Connection Pool Exhausted
    Type: metric alert
    Query: |
      avg(last_5m):
        avg:payments_platform.db.pool.available{*} < 2
    Message: |
      Database connection pool is almost exhausted
      
      Available connections: {{value}}
      
      @pagerduty-database @slack-devops
    Thresholds:
      critical: 1
      warning: 2
  
  - Name: Circuit Breaker Open
    Type: metric alert
    Query: |
      max(last_5m):
        max:payments_platform.circuit_breaker.state{*} > 0
    Message: |
      Circuit breaker is OPEN for {{gateway.name}}
      
      Gateway is unavailable or experiencing high error rate
      
      @pagerduty-payments @slack-alerts
    Thresholds:
      critical: 1
  
  - Name: DLQ Depth High
    Type: metric alert
    Query: |
      avg(last_10m):
        avg:aws.sqs.approximate_number_of_messages_visible{queue:payment-dlq} > 100
    Message: |
      Dead Letter Queue has {{value}} messages
      
      Payments are failing persistently
      
      @pagerduty-payments @slack-alerts
    Thresholds:
      critical: 500
      warning: 100
```

#### 6.1.3 Alertas de Segurança
```yaml
Monitors:
  - Name: High Failed Login Attempts
    Type: log alert
    Query: |
      logs("service:user-service action:auth.login.failed").rollup("count").last("5m") > 50
    Message: |
      High number of failed login attempts: {{value}}
      
      Possible brute force attack
      
      @security-team @slack-security
    Thresholds:
      critical: 100
      warning: 50
  
  - Name: Unusual API Call Pattern
    Type: anomaly alert
    Query: |
      anomalies(avg(last_4h):
        sum:payments_platform.api.requests{*}.as_count(), 'basic', 2)
    Message: |
      Unusual API call pattern detected
      
      Possible DDoS or abuse
      
      @security-team @slack-security
```

---

### 6.2 Escalation Policy

#### 6.2.1 Níveis de Severidade
```yaml
Severity_Levels:
  P1_Critical:
    Description: Sistema completamente indisponível ou perda de dados
    Response_Time: 15 minutos
    Escalation:
      - Immediate: On-call engineer
      - 15min: Engineering manager
      - 30min: CTO
    Examples:
      - Payments service down
      - Database unavailable
      - Data breach
  
  P2_High:
    Description: Funcionalidade crítica degradada
    Response_Time: 30 minutos
    Escalation:
      - Immediate: On-call engineer
      - 30min: Engineering manager
    Examples:
      - High error rate (>5%)
      - Gateway unavailable
      - Slow performance
  
  P3_Medium:
    Description: Funcionalidade não-crítica afetada
    Response_Time: 2 horas
    Escalation:
      - Immediate: On-call engineer
    Examples:
      - Notification delays
      - Report generation slow
      - Cache misses high
  
  P4_Low:
    Description: Problema menor sem impacto imediato
    Response_Time: Next business day
    Escalation:
      - Ticket created
    Examples:
      - Log volume high
      - Minor UI issues
```

#### 6.2.2 On-Call Rotation
```yaml
On_Call_Schedule:
  Primary:
    Rotation: Weekly
    Team: Backend Engineers
    Coverage: 24/7
  
  Secondary:
    Rotation: Weekly
    Team: Senior Engineers
    Coverage: 24/7
  
  Escalation:
    Level_1: Engineering Manager
    Level_2: CTO
  
  Tools:
    - PagerDuty
    - Slack
    - Phone
```

---

## 7. Estratégias de Deploy

### 7.1 Blue-Green Deployment

#### 7.1.1 Propósito
- Zero downtime
- Rollback instantâneo
- Testes em produção

#### 7.1.2 Processo
```yaml
Blue_Green_Deployment:
  Steps:
    1_Prepare:
      - Build new version (Green)
      - Deploy to Green environment
      - Run smoke tests
    
    2_Switch:
      - Update ALB target group to Green
      - Monitor metrics for 10 minutes
      - Verify no errors
    
    3_Cleanup:
      - If successful: Decommission Blue
      - If failed: Rollback to Blue
  
  Configuration:
    Blue_Environment:
      TargetGroup: payments-service-blue-tg
      Tasks: 3
    
    Green_Environment:
      TargetGroup: payments-service-green-tg
      Tasks: 3
    
    ALB_Listener:
      DefaultAction: Forward to Blue
      SwitchAction: Forward to Green
```

#### 7.1.3 Implementação
```bash
#!/bin/bash
# blue-green-deploy.sh

# 1. Deploy Green
aws ecs update-service \
  --cluster payments-cluster \
  --service payments-service-green \
  --task-definition payments-service:$NEW_VERSION \
  --desired-count 3

# 2. Wait for Green to be healthy
aws ecs wait services-stable \
  --cluster payments-cluster \
  --services payments-service-green

# 3. Run smoke tests
./smoke-tests.sh green

# 4. Switch traffic
aws elbv2 modify-listener \
  --listener-arn $LISTENER_ARN \
  --default-actions Type=forward,TargetGroupArn=$GREEN_TG_ARN

# 5. Monitor for 10 minutes
sleep 600

# 6. Check error rate
ERROR_RATE=$(datadog-cli metric get payment.error.rate --last 10m)

if [ $ERROR_RATE -lt 1 ]; then
  echo "Deployment successful"
  # Decommission Blue
  aws ecs update-service \
    --cluster payments-cluster \
    --service payments-service-blue \
    --desired-count 0
else
  echo "Deployment failed, rolling back"
  # Rollback to Blue
  aws elbv2 modify-listener \
    --listener-arn $LISTENER_ARN \
    --default-actions Type=forward,TargetGroupArn=$BLUE_TG_ARN
fi
```

---

### 7.2 Canary Deployment

#### 7.2.1 Propósito
- Reduzir risco de deploy
- Testar com tráfego real limitado
- Detecção precoce de problemas

#### 7.2.2 Processo
```yaml
Canary_Deployment:
  Stages:
    Stage_1_Canary_10:
      Traffic: 10%
      Duration: 15 minutes
      Success_Criteria:
        - Error rate < 1%
        - Latency P95 < 3s
        - No critical alerts
    
    Stage_2_Canary_50:
      Traffic: 50%
      Duration: 30 minutes
      Success_Criteria:
        - Error rate < 1%
        - Latency P95 < 3s
        - No critical alerts
    
    Stage_3_Full:
      Traffic: 100%
      Duration: Ongoing
      Success_Criteria:
        - Error rate < 1%
        - Latency P95 < 3s
  
  Rollback_Triggers:
    - Error rate > 2%
    - Latency P95 > 5s
    - Critical alert fired
    - Manual intervention
```

#### 7.2.3 Implementação com ALB
```json
{
  "Listener": {
    "DefaultActions": [
      {
        "Type": "forward",
        "ForwardConfig": {
          "TargetGroups": [
            {
              "TargetGroupArn": "arn:aws:elasticloadbalancing:...:stable",
              "Weight": 90
            },
            {
              "TargetGroupArn": "arn:aws:elasticloadbalancing:...:canary",
              "Weight": 10
            }
          ],
          "TargetGroupStickinessConfig": {
            "Enabled": true,
            "DurationSeconds": 3600
          }
        }
      }
    ]
  }
}
```

---

### 7.3 Rolling Update

#### 7.3.1 Propósito
- Deploy gradual
- Manter disponibilidade
- Reduzir impacto de falhas

#### 7.3.2 Configuração ECS
```json
{
  "DeploymentConfiguration": {
    "MaximumPercent": 200,
    "MinimumHealthyPercent": 100,
    "DeploymentCircuitBreaker": {
      "Enable": true,
      "Rollback": true
    }
  },
  "HealthCheckGracePeriodSeconds": 60
}
```

#### 7.3.3 Processo
```
Initial State: 6 tasks running (v1.0)

Step 1: Start 3 new tasks (v1.1)
  [v1.0] [v1.0] [v1.0] [v1.0] [v1.0] [v1.0]
  [v1.1] [v1.1] [v1.1]

Step 2: Wait for health checks

Step 3: Stop 3 old tasks
  [v1.0] [v1.0] [v1.0]
  [v1.1] [v1.1] [v1.1]

Step 4: Start 3 more new tasks
  [v1.0] [v1.0] [v1.0]
  [v1.1] [v1.1] [v1.1] [v1.1] [v1.1] [v1.1]

Step 5: Wait for health checks

Step 6: Stop remaining old tasks
  [v1.1] [v1.1] [v1.1] [v1.1] [v1.1] [v1.1]

Final State: 6 tasks running (v1.1)
```

---

## 8. Disaster Recovery

### 8.1 Backup Strategy

#### 8.1.1 RDS Automated Backups
```yaml
RDS_Backups:
  Automated:
    Enabled: true
    RetentionPeriod: 30 days
    BackupWindow: "03:00-04:00 UTC"
    PreferredMaintenanceWindow: "sun:04:00-sun:05:00 UTC"
  
  Snapshots:
    Manual:
      - Before major deployments
      - Before schema changes
      - Monthly full snapshots
    Retention: 90 days
  
  Point_In_Time_Recovery:
    Enabled: true
    RetentionPeriod: 30 days
```

#### 8.1.2 DocumentDB Backups
```yaml
DocumentDB_Backups:
  Automated:
    Enabled: true
    RetentionPeriod: 7 days
    BackupWindow: "03:00-04:00 UTC"
  
  Snapshots:
    Manual:
      - Weekly full snapshots
    Retention: 30 days
```

#### 8.1.3 S3 Versioning e Lifecycle
```json
{
  "VersioningConfiguration": {
    "Status": "Enabled"
  },
  "LifecycleConfiguration": {
    "Rules": [
      {
        "Id": "archive-old-versions",
        "Status": "Enabled",
        "NoncurrentVersionTransitions": [
          {
            "NoncurrentDays": 30,
            "StorageClass": "STANDARD_IA"
          },
          {
            "NoncurrentDays": 90,
            "StorageClass": "GLACIER"
          }
        ],
        "NoncurrentVersionExpiration": {
          "NoncurrentDays": 365
        }
      }
    ]
  }
}
```

---

### 8.2 Recovery Procedures

#### 8.2.1 RTO e RPO
```yaml
Recovery_Objectives:
  RTO_Recovery_Time_Objective:
    P1_Critical: 1 hour
    P2_High: 4 hours
    P3_Medium: 24 hours
  
  RPO_Recovery_Point_Objective:
    Database: 5 minutes (PITR)
    Files: 24 hours (daily backup)
    Logs: 0 (real-time replication)
```

#### 8.2.2 Disaster Recovery Plan
```yaml
DR_Plan:
  Scenario_1_Database_Failure:
    Detection:
      - CloudWatch alarm
      - Health check failure
      - Application errors
    
    Response:
      1. Verify failure scope
      2. Initiate failover to standby (Multi-AZ)
      3. Update DNS if needed
      4. Verify application connectivity
      5. Monitor for 30 minutes
    
    Expected_Downtime: 5-10 minutes
  
  Scenario_2_Region_Failure:
    Detection:
      - Multiple service failures
      - AWS status page
      - Network connectivity issues
    
    Response:
      1. Activate DR region
      2. Restore latest database snapshot
      3. Update Route53 to DR region
      4. Deploy application to DR region
      5. Verify functionality
      6. Communicate to users
    
    Expected_Downtime: 2-4 hours
  
  Scenario_3_Data_Corruption:
    Detection:
      - Data validation errors
      - User reports
      - Audit log anomalies
    
    Response:
      1. Identify corruption scope
      2. Stop writes to affected tables
      3. Restore from point-in-time backup
      4. Replay transactions if needed
      5. Verify data integrity
      6. Resume operations
    
    Expected_Downtime: 1-2 hours
```

#### 8.2.3 Runbooks
```markdown
# Runbook: Database Failover

## Trigger
- RDS instance unavailable
- High latency (>5s)
- Connection errors

## Prerequisites
- Multi-AZ enabled
- Standby instance healthy
- Backup recent (<24h)

## Steps
1. Verify primary instance status
   ```bash
   aws rds describe-db-instances --db-instance-identifier payments-db
   ```

2. Check standby instance
   ```bash
   aws rds describe-db-instances --db-instance-identifier payments-db-standby
   ```

3. Initiate failover
   ```bash
   aws rds reboot-db-instance \
     --db-instance-identifier payments-db \
     --force-failover
   ```

4. Monitor failover progress
   ```bash
   aws rds wait db-instance-available \
     --db-instance-identifier payments-db
   ```

5. Verify application connectivity
   ```bash
   curl https://api.payments-platform.com/health
   ```

6. Check error rates in Datadog
   - Navigate to Payments Dashboard
   - Verify error rate < 1%
   - Check latency P95 < 3s

7. Document incident
   - Create post-mortem
   - Update runbook if needed

## Rollback
If failover fails:
1. Restore from latest snapshot
2. Update connection strings
3. Restart application services
```

---

## 9. Referências

- Documento de Cenários: `0-scenarios.md`
- Documento de Mapeamento de Serviços: `1-service-map.md`
- Documento de Stack Tecnológica: `2-tech-stack.md`
- Documento de Estratégia de Integração: `3-integration-stratefy.md`
- Documento de Segurança: `4-security.md`
- Documento de Evolução: `8-evolution.md`
