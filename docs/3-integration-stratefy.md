# Documentação: Estratégia de Integração com Gateways de Pagamento

## 1. Visão Geral

Este documento detalha as estratégias, padrões e práticas recomendadas para integração com gateways de pagamento externos (Stone, Getnet e futuros parceiros). O foco está em resiliência, segurança, auditabilidade e conformidade com regulações financeiras.

## 2. Contexto e Objetivos

### 2.1 Desafios de Integração
- **Disponibilidade**: Gateways podem estar indisponíveis
- **Latência**: Variação de performance entre gateways
- **Consistência**: Garantir estado consistente em falhas
- **Segurança**: Proteção de dados sensíveis (PCI-DSS)
- **Auditoria**: Rastreabilidade completa de transações
- **Compliance**: LGPD, GDPR, BACEN

### 2.2 Objetivos
- Garantir 99.9%+ de disponibilidade de processamento
- Tempo de resposta P95 < 3 segundos
- Zero perda de transações
- 100% de auditabilidade
- Isolamento de falhas por gateway
- Facilidade de adicionar novos gateways

## 3. Arquitetura de Integração

### 3.1 Visão Geral
```
┌─────────────────────────────────────────────────────────┐
│                  Payments Service                        │
│              (Orquestrador Principal)                    │
└─────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────┐
│                   Store Service                          │
│            (Roteamento e Seleção de Gateway)            │
└─────────────────────────────────────────────────────────┘
                           ↓
        ┌──────────────────┴──────────────────┐
        ↓                                      ↓
┌──────────────────┐                  ┌──────────────────┐
│  Getnet Service  │                  │  Stone Service   │
│   (Integração)   │                  │   (Integração)   │
└──────────────────┘                  └──────────────────┘
        ↓                                      ↓
┌──────────────────┐                  ┌──────────────────┐
│   Getnet API     │                  │   Stone API      │
│   (External)     │                  │   (External)     │
└──────────────────┘                  └──────────────────┘
```

### 3.2 Princípios Arquiteturais
- **Isolamento**: Cada gateway tem seu próprio microserviço
- **Desacoplamento**: Comunicação via eventos e APIs
- **Resiliência**: Circuit breaker, retry, timeout
- **Idempotência**: Prevenção de duplicação
- **Auditabilidade**: 100% de requests/responses armazenados

## 4. Participantes

### 4.1 Getnet

#### 4.1.1 Características
- **Tipo**: Adquirente e gateway de pagamento
- **Métodos**: Crédito, débito, PIX
- **Bandeiras**: Visa, Mastercard, Elo, Amex
- **SLA**: 99.5% de disponibilidade
- **Latência Média**: 800ms

#### 4.1.2 Endpoints Principais
```
POST   /v1/payments/credit/authorize
POST   /v1/payments/credit/capture
POST   /v1/payments/credit/cancel
POST   /v1/payments/debit/authorize
GET    /v1/payments/{payment_id}
POST   /v1/payments/refund
```

#### 4.1.3 Autenticação
- OAuth 2.0 Client Credentials
- Token expira em 1 hora
- Refresh automático

---

### 4.2 Stone

#### 4.2.1 Características
- **Tipo**: Adquirente e gateway de pagamento
- **Métodos**: Crédito, débito, PIX, boleto
- **Bandeiras**: Visa, Mastercard, Elo
- **SLA**: 99.7% de disponibilidade
- **Latência Média**: 600ms

#### 4.2.2 Endpoints Principais
```
POST   /api/v2/charges
GET    /api/v2/charges/{charge_id}
POST   /api/v2/charges/{charge_id}/capture
POST   /api/v2/charges/{charge_id}/cancel
POST   /api/v2/refunds
```

#### 4.2.3 Autenticação
- API Key no header
- Secret Key para assinatura de requests

---

## 5. Padrões de Resiliência

### 5.1 Circuit Breaker

#### 5.1.1 Propósito
Prevenir cascata de falhas quando gateway está indisponível.

#### 5.1.2 Estados
- **CLOSED**: Funcionamento normal
- **OPEN**: Gateway indisponível, rejeita requisições
- **HALF_OPEN**: Testando recuperação

#### 5.1.3 Configuração
```typescript
// circuit-breaker.config.ts
export const circuitBreakerConfig = {
  timeout: 5000,                    // 5 segundos
  errorThresholdPercentage: 50,     // 50% de erro
  resetTimeout: 30000,              // 30 segundos para tentar novamente
  rollingCountTimeout: 10000,       // Janela de 10 segundos
  rollingCountBuckets: 10,          // 10 buckets
  name: 'getnet-circuit-breaker',
  fallback: async () => {
    // Tentar gateway alternativo
    return await stoneService.processPayment();
  }
};
```

#### 5.1.4 Implementação
```typescript
import CircuitBreaker from 'opossum';

@Injectable()
export class GetnetService {
  private circuitBreaker: CircuitBreaker;
  
  constructor(
    private readonly httpService: HttpService,
    private readonly logger: Logger
  ) {
    this.circuitBreaker = new CircuitBreaker(
      this.callGetnetAPI.bind(this),
      circuitBreakerConfig
    );
    
    // Event listeners
    this.circuitBreaker.on('open', () => {
      this.logger.error('Circuit breaker OPEN - Getnet unavailable');
      // Publish event for monitoring
      this.eventEmitter.emit('gateway.circuit.open', { gateway: 'getnet' });
    });
    
    this.circuitBreaker.on('halfOpen', () => {
      this.logger.warn('Circuit breaker HALF_OPEN - Testing Getnet');
    });
    
    this.circuitBreaker.on('close', () => {
      this.logger.info('Circuit breaker CLOSED - Getnet recovered');
      this.eventEmitter.emit('gateway.circuit.closed', { gateway: 'getnet' });
    });
  }
  
  async processPayment(payment: Payment): Promise<GatewayResponse> {
    try {
      return await this.circuitBreaker.fire(payment);
    } catch (error) {
      if (error.message === 'Breaker is open') {
        // Fallback para gateway alternativo
        return await this.fallbackToStone(payment);
      }
      throw error;
    }
  }
  
  private async callGetnetAPI(payment: Payment): Promise<GatewayResponse> {
    const response = await this.httpService.post(
      '/v1/payments/credit/authorize',
      this.transformRequest(payment),
      { timeout: 5000 }
    ).toPromise();
    
    return this.transformResponse(response.data);
  }
}
```

#### 5.1.5 Exemplo de Fluxo
```
1. Request 1-10: Sucesso (Circuit CLOSED)
2. Request 11-15: Timeout (50% erro)
3. Circuit abre (OPEN)
4. Request 16-20: Rejeitadas imediatamente, usa fallback
5. Após 30s: Circuit tenta (HALF_OPEN)
6. Request 21: Sucesso
7. Circuit fecha (CLOSED)
```

---

### 5.2 Retry com Exponential Backoff

#### 5.2.1 Propósito
Retentar requisições falhas com intervalos crescentes.

#### 5.2.2 Estratégia
- **Erros Retryable**: 5xx, timeout, network errors
- **Erros Não-Retryable**: 4xx (exceto 429), validation errors
- **Max Retries**: 3 tentativas
- **Backoff**: Exponencial com jitter

#### 5.2.3 Implementação
```typescript
import { retry, RetryConfig } from 'ts-retry-promise';

@Injectable()
export class GetnetService {
  private readonly retryConfig: RetryConfig<any> = {
    retries: 3,
    delay: 1000,              // 1 segundo inicial
    backoff: 'EXPONENTIAL',   // 1s, 2s, 4s
    timeout: 15000,           // 15 segundos total
    retryIf: (error: any) => {
      // Retry apenas em erros temporários
      return (
        error.response?.status >= 500 ||
        error.code === 'ECONNABORTED' ||
        error.code === 'ETIMEDOUT'
      );
    },
    logger: (msg) => this.logger.debug(msg)
  };
  
  async authorizePayment(payment: Payment): Promise<GatewayResponse> {
    return retry(
      async () => {
        const startTime = Date.now();
        
        try {
          const response = await this.httpService.post(
            '/v1/payments/credit/authorize',
            this.transformRequest(payment),
            {
              timeout: 5000,
              headers: {
                'X-Idempotency-Key': payment.idempotencyKey
              }
            }
          ).toPromise();
          
          const duration = Date.now() - startTime;
          
          // Log sucesso
          this.logger.info({
            action: 'getnet.authorize.success',
            paymentId: payment.id,
            duration
          });
          
          return this.transformResponse(response.data);
          
        } catch (error) {
          const duration = Date.now() - startTime;
          
          // Log erro
          this.logger.error({
            action: 'getnet.authorize.error',
            paymentId: payment.id,
            duration,
            error: error.message,
            statusCode: error.response?.status
          });
          
          throw error;
        }
      },
      this.retryConfig
    );
  }
}
```

#### 5.2.4 Exemplo de Fluxo
```
Tentativa 1: Timeout após 5s
  ↓ Aguarda 1s
Tentativa 2: 503 Service Unavailable
  ↓ Aguarda 2s
Tentativa 3: 200 OK (Sucesso)

Total: ~8 segundos
```

---

### 5.3 Timeout

#### 5.3.1 Propósito
Prevenir requisições infinitas que bloqueiam recursos.

#### 5.3.2 Configuração por Operação
```typescript
export const timeoutConfig = {
  authorize: 5000,      // 5 segundos
  capture: 3000,        // 3 segundos
  cancel: 3000,         // 3 segundos
  refund: 5000,         // 5 segundos
  query: 2000           // 2 segundos
};
```

#### 5.3.3 Implementação
```typescript
import axios, { AxiosInstance } from 'axios';
import axiosRetry from 'axios-retry';

@Injectable()
export class GetnetHttpClient {
  private readonly client: AxiosInstance;
  
  constructor() {
    this.client = axios.create({
      baseURL: process.env.GETNET_API_URL,
      timeout: 5000,  // Default timeout
      headers: {
        'Content-Type': 'application/json'
      }
    });
    
    // Request interceptor
    this.client.interceptors.request.use(
      (config) => {
        config.metadata = { startTime: Date.now() };
        return config;
      }
    );
    
    // Response interceptor
    this.client.interceptors.response.use(
      (response) => {
        const duration = Date.now() - response.config.metadata.startTime;
        response.duration = duration;
        return response;
      },
      (error) => {
        if (error.code === 'ECONNABORTED') {
          error.isTimeout = true;
        }
        throw error;
      }
    );
  }
  
  async post(url: string, data: any, timeout?: number): Promise<any> {
    return this.client.post(url, data, {
      timeout: timeout || timeoutConfig.authorize
    });
  }
}
```

---

### 5.4 Idempotência

#### 5.4.1 Propósito
Garantir que requisições duplicadas não criem múltiplas transações.

#### 5.4.2 Estratégia
- **Idempotency Key**: UUID único por transação
- **Storage**: Redis com TTL de 24 horas
- **Header**: `X-Idempotency-Key`

#### 5.4.3 Implementação
```typescript
@Injectable()
export class IdempotencyService {
  constructor(
    private readonly redis: Redis,
    private readonly logger: Logger
  ) {}
  
  async checkIdempotency(key: string): Promise<any | null> {
    const cached = await this.redis.get(`idempotency:${key}`);
    
    if (cached) {
      this.logger.warn({
        action: 'idempotency.hit',
        key
      });
      return JSON.parse(cached);
    }
    
    return null;
  }
  
  async storeIdempotency(key: string, response: any): Promise<void> {
    await this.redis.setex(
      `idempotency:${key}`,
      86400,  // 24 horas
      JSON.stringify(response)
    );
  }
}

@Injectable()
export class PaymentsService {
  async createPayment(dto: CreatePaymentDto): Promise<Payment> {
    // Gerar idempotency key se não fornecida
    const idempotencyKey = dto.idempotencyKey || uuidv4();
    
    // Verificar se já foi processado
    const existing = await this.idempotencyService.checkIdempotency(
      idempotencyKey
    );
    
    if (existing) {
      return existing;
    }
    
    // Processar pagamento
    const payment = await this.processPayment({
      ...dto,
      idempotencyKey
    });
    
    // Armazenar resultado
    await this.idempotencyService.storeIdempotency(
      idempotencyKey,
      payment
    );
    
    return payment;
  }
}
```

---

### 5.5 Outbox Pattern

#### 5.5.1 Propósito
Garantir que eventos sejam publicados mesmo em caso de falhas.

#### 5.5.2 Estratégia
- Salvar evento na mesma transação do banco
- Processo separado publica eventos pendentes
- Marca evento como publicado após sucesso

#### 5.5.3 Implementação
```typescript
// outbox.entity.ts
@Entity('outbox_events')
export class OutboxEvent {
  @PrimaryGeneratedColumn('uuid')
  id: string;
  
  @Column()
  aggregateId: string;
  
  @Column()
  eventType: string;
  
  @Column('jsonb')
  payload: any;
  
  @Column({ default: false })
  published: boolean;
  
  @Column({ nullable: true })
  publishedAt: Date;
  
  @CreateDateColumn()
  createdAt: Date;
  
  @Column({ default: 0 })
  retryCount: number;
}

// payments.service.ts
@Injectable()
export class PaymentsService {
  async completePayment(paymentId: string): Promise<void> {
    await this.dataSource.transaction(async (manager) => {
      // Atualizar pagamento
      await manager.update(Payment, paymentId, {
        status: PaymentStatus.COMPLETED
      });
      
      // Salvar evento no outbox
      await manager.save(OutboxEvent, {
        aggregateId: paymentId,
        eventType: 'payment.completed',
        payload: {
          paymentId,
          completedAt: new Date()
        }
      });
    });
  }
}

// outbox.processor.ts
@Injectable()
export class OutboxProcessor {
  @Cron('*/10 * * * * *')  // A cada 10 segundos
  async processOutbox(): Promise<void> {
    const events = await this.outboxRepository.find({
      where: { published: false },
      take: 100,
      order: { createdAt: 'ASC' }
    });
    
    for (const event of events) {
      try {
        // Publicar evento
        await this.eventBridge.putEvents({
          Entries: [{
            Source: 'payments.service',
            DetailType: event.eventType,
            Detail: JSON.stringify(event.payload)
          }]
        }).promise();
        
        // Marcar como publicado
        await this.outboxRepository.update(event.id, {
          published: true,
          publishedAt: new Date()
        });
        
      } catch (error) {
        // Incrementar retry count
        await this.outboxRepository.update(event.id, {
          retryCount: event.retryCount + 1
        });
        
        // Se excedeu max retries, alertar
        if (event.retryCount >= 5) {
          this.logger.error({
            action: 'outbox.max_retries',
            eventId: event.id
          });
        }
      }
    }
  }
}
```

---

## 6. Armazenamento de Auditoria

### 6.1 Propósito
Armazenar 100% dos requests e responses para:
- Auditoria financeira
- Troubleshooting
- Compliance (BACEN, LGPD)
- Análise de performance

### 6.2 Estrutura de Dados
```typescript
// gateway-audit.schema.ts
@Schema({ collection: 'gateway_audit', timestamps: true })
export class GatewayAudit {
  @Prop({ required: true, index: true })
  transactionId: string;
  
  @Prop({ required: true })
  gateway: string;  // 'getnet', 'stone'
  
  @Prop({ required: true })
  operation: string;  // 'authorize', 'capture', 'cancel'
  
  @Prop({ type: Object })
  request: {
    url: string;
    method: string;
    headers: Record<string, string>;
    body: any;
  };
  
  @Prop({ type: Object })
  response: {
    statusCode: number;
    headers: Record<string, string>;
    body: any;
  };
  
  @Prop()
  duration: number;  // milliseconds
  
  @Prop()
  success: boolean;
  
  @Prop()
  errorMessage?: string;
  
  @Prop({ type: Date, expires: '2y' })  // TTL de 2 anos
  createdAt: Date;
}
```

### 6.3 Implementação
```typescript
@Injectable()
export class GatewayAuditService {
  constructor(
    @InjectModel(GatewayAudit.name)
    private readonly auditModel: Model<GatewayAudit>
  ) {}
  
  async logRequest(data: {
    transactionId: string;
    gateway: string;
    operation: string;
    request: any;
    response: any;
    duration: number;
    success: boolean;
    errorMessage?: string;
  }): Promise<void> {
    // Anonimizar dados sensíveis
    const sanitizedRequest = this.sanitize(data.request);
    const sanitizedResponse = this.sanitize(data.response);
    
    await this.auditModel.create({
      ...data,
      request: sanitizedRequest,
      response: sanitizedResponse
    });
  }
  
  private sanitize(obj: any): any {
    const sensitive = [
      'cardNumber',
      'cvv',
      'password',
      'token',
      'authorization'
    ];
    
    const sanitized = JSON.parse(JSON.stringify(obj));
    
    const mask = (o: any) => {
      for (const key in o) {
        if (sensitive.includes(key)) {
          o[key] = '***REDACTED***';
        } else if (typeof o[key] === 'object') {
          mask(o[key]);
        }
      }
    };
    
    mask(sanitized);
    return sanitized;
  }
}
```

### 6.4 Uso no Gateway Service
```typescript
@Injectable()
export class GetnetService {
  async authorizePayment(payment: Payment): Promise<GatewayResponse> {
    const startTime = Date.now();
    let request: any;
    let response: any;
    let success = false;
    let errorMessage: string;
    
    try {
      request = this.transformRequest(payment);
      
      const result = await this.httpClient.post(
        '/v1/payments/credit/authorize',
        request
      );
      
      response = result.data;
      success = true;
      
      return this.transformResponse(response);
      
    } catch (error) {
      errorMessage = error.message;
      response = error.response?.data;
      throw error;
      
    } finally {
      const duration = Date.now() - startTime;
      
      // Sempre armazenar auditoria
      await this.auditService.logRequest({
        transactionId: payment.id,
        gateway: 'getnet',
        operation: 'authorize',
        request,
        response,
        duration,
        success,
        errorMessage
      });
    }
  }
}
```

---

## 7. Logging e Anonimização

### 7.1 Propósito
- Centralizar logs para troubleshooting
- Anonimizar dados sensíveis (LGPD/GDPR)
- Integrar com CloudWatch e Datadog

### 7.2 Dados Sensíveis a Anonimizar
- Número de cartão (PAN)
- CVV
- Senha
- CPF/CNPJ completo
- Email completo
- Telefone completo
- Tokens de autenticação

### 7.3 Implementação
```typescript
// logger.service.ts
@Injectable()
export class LoggerService {
  private readonly logger: pino.Logger;
  
  constructor() {
    this.logger = pino({
      level: process.env.LOG_LEVEL || 'info',
      redact: {
        paths: [
          'req.headers.authorization',
          'req.body.cardNumber',
          'req.body.cvv',
          'req.body.password',
          'res.body.token',
          '*.cardNumber',
          '*.cvv',
          '*.password'
        ],
        censor: '***REDACTED***'
      },
      serializers: {
        cardNumber: (value) => {
          if (!value) return value;
          // Mostrar apenas últimos 4 dígitos
          return `****-****-****-${value.slice(-4)}`;
        },
        cpf: (value) => {
          if (!value) return value;
          // Mostrar apenas últimos 3 dígitos
          return `***.***.***-${value.slice(-2)}`;
        },
        email: (value) => {
          if (!value) return value;
          const [user, domain] = value.split('@');
          return `${user.slice(0, 2)}***@${domain}`;
        }
      }
    });
  }
  
  info(obj: any, msg?: string): void {
    this.logger.info(this.anonymize(obj), msg);
  }
  
  error(obj: any, msg?: string): void {
    this.logger.error(this.anonymize(obj), msg);
  }
  
  private anonymize(obj: any): any {
    // Implementação de anonimização recursiva
    // ...
  }
}
```

### 7.4 Exemplo de Log
```json
{
  "level": "info",
  "time": 1234567890,
  "action": "payment.authorize",
  "paymentId": "uuid-123",
  "userId": "uuid-456",
  "amount": 100.00,
  "cardNumber": "****-****-****-1234",
  "gateway": "getnet",
  "duration": 850,
  "success": true
}
```

---

## 8. Tratamento de Erros

### 8.1 Cenário: Gateway Indisponível

#### 8.1.1 Estratégia
1. **Retry**: 3 tentativas com exponential backoff
2. **Circuit Breaker**: Abre após 50% de erro
3. **Fallback**: Tenta gateway alternativo
4. **Dead Letter Queue**: Armazena falhas persistentes
5. **Notificação**: Alerta equipe de operações

#### 8.1.2 Implementação
```typescript
@Injectable()
export class PaymentsOrchestrator {
  async processPayment(payment: Payment): Promise<PaymentResult> {
    try {
      // Tentar gateway primário (Getnet)
      return await this.getnetService.authorize(payment);
      
    } catch (error) {
      if (error.message === 'Breaker is open') {
        this.logger.warn({
          action: 'gateway.fallback',
          from: 'getnet',
          to: 'stone',
          paymentId: payment.id
        });
        
        // Fallback para Stone
        try {
          return await this.stoneService.authorize(payment);
        } catch (fallbackError) {
          // Ambos falharam, enviar para DLQ
          await this.sendToDLQ(payment, {
            primaryError: error,
            fallbackError
          });
          
          throw new GatewayUnavailableException(
            'All payment gateways are unavailable'
          );
        }
      }
      
      throw error;
    }
  }
  
  private async sendToDLQ(
    payment: Payment,
    errors: any
  ): Promise<void> {
    await this.sqs.sendMessage({
      QueueUrl: process.env.PAYMENT_DLQ_URL,
      MessageBody: JSON.stringify({
        payment,
        errors,
        timestamp: new Date().toISOString(),
        retryCount: 0
      })
    }).promise();
    
    // Atualizar status do pagamento
    await this.paymentsRepository.update(payment.id, {
      status: PaymentStatus.PENDING_RETRY
    });
    
    // Notificar usuário
    await this.notificationService.send({
      userId: payment.userId,
      type: 'payment.delayed',
      message: 'Seu pagamento está sendo processado e será confirmado em breve.'
    });
  }
}
```

#### 8.1.3 Processamento da DLQ
```typescript
@Injectable()
export class DLQProcessor {
  @Cron('*/5 * * * *')  // A cada 5 minutos
  async processDLQ(): Promise<void> {
    const messages = await this.sqs.receiveMessage({
      QueueUrl: process.env.PAYMENT_DLQ_URL,
      MaxNumberOfMessages: 10,
      WaitTimeSeconds: 20
    }).promise();
    
    for (const message of messages.Messages || []) {
      const data = JSON.parse(message.Body);
      
      // Verificar se já excedeu max retries
      if (data.retryCount >= 5) {
        // Mover para fila de falhas permanentes
        await this.handlePermanentFailure(data);
        continue;
      }
      
      try {
        // Tentar processar novamente
        await this.paymentsOrchestrator.processPayment(data.payment);
        
        // Sucesso, deletar da DLQ
        await this.sqs.deleteMessage({
          QueueUrl: process.env.PAYMENT_DLQ_URL,
          ReceiptHandle: message.ReceiptHandle
        }).promise();
        
      } catch (error) {
        // Incrementar retry count e reenviar
        data.retryCount++;
        await this.sqs.sendMessage({
          QueueUrl: process.env.PAYMENT_DLQ_URL,
          MessageBody: JSON.stringify(data),
          DelaySeconds: Math.min(data.retryCount * 60, 900)  // Max 15 min
        }).promise();
      }
    }
  }
}
```

---

### 8.2 Cenário: Falha Parcial

#### 8.2.1 Estratégia
- Garantir consistência eventual
- Notificar usuário do status
- Implementar compensação se necessário

#### 8.2.2 Exemplo: Autorização OK, Captura Falhou
```typescript
@Injectable()
export class PaymentsService {
  async capturePayment(paymentId: string): Promise<void> {
    const payment = await this.paymentsRepository.findOne(paymentId);
    
    if (payment.status !== PaymentStatus.AUTHORIZED) {
      throw new InvalidStatusException();
    }
    
    try {
      // Tentar capturar
      await this.getnetService.capture(payment);
      
      // Atualizar status
      await this.paymentsRepository.update(paymentId, {
        status: PaymentStatus.CAPTURED
      });
      
      // Publicar evento
      this.eventEmitter.emit('payment.captured', { paymentId });
      
    } catch (error) {
      // Captura falhou, mas autorização ainda válida
      this.logger.error({
        action: 'payment.capture.failed',
        paymentId,
        error: error.message
      });
      
      // Agendar retry
      await this.scheduleRetry(paymentId, 'capture');
      
      // Notificar usuário
      await this.notificationService.send({
        userId: payment.userId,
        type: 'payment.processing',
        message: 'Seu pagamento está sendo processado.'
      });
    }
  }
  
  private async scheduleRetry(
    paymentId: string,
    operation: string
  ): Promise<void> {
    await this.sqs.sendMessage({
      QueueUrl: process.env.PAYMENT_RETRY_QUEUE_URL,
      MessageBody: JSON.stringify({
        paymentId,
        operation,
        scheduledAt: new Date().toISOString()
      }),
      DelaySeconds: 300  // 5 minutos
    }).promise();
  }
}
```

---

### 8.3 Cenário: Timeout

#### 8.3.1 Estratégia
- Consultar status no gateway
- Reconciliar estado
- Evitar duplicação

#### 8.3.2 Implementação
```typescript
@Injectable()
export class PaymentsService {
  async handleTimeout(payment: Payment): Promise<void> {
    this.logger.warn({
      action: 'payment.timeout',
      paymentId: payment.id
    });
    
    // Aguardar alguns segundos
    await this.sleep(5000);
    
    try {
      // Consultar status no gateway
      const status = await this.getnetService.queryPayment(
        payment.gatewayTransactionId
      );
      
      // Reconciliar estado
      await this.reconcilePaymentStatus(payment.id, status);
      
    } catch (error) {
      // Não conseguiu consultar, agendar reconciliação
      await this.scheduleReconciliation(payment.id);
    }
  }
  
  private async reconcilePaymentStatus(
    paymentId: string,
    gatewayStatus: any
  ): Promise<void> {
    const localPayment = await this.paymentsRepository.findOne(paymentId);
    
    // Mapear status do gateway para status local
    const mappedStatus = this.mapGatewayStatus(gatewayStatus);
    
    if (localPayment.status !== mappedStatus) {
      this.logger.info({
        action: 'payment.reconciled',
        paymentId,
        oldStatus: localPayment.status,
        newStatus: mappedStatus
      });
      
      await this.paymentsRepository.update(paymentId, {
        status: mappedStatus
      });
      
      // Publicar evento de reconciliação
      this.eventEmitter.emit('payment.reconciled', {
        paymentId,
        status: mappedStatus
      });
    }
  }
}
```

---

## 9. Isolamento de Domínio

### 9.1 Propósito
Cada gateway tem seu próprio microserviço para:
- Isolamento de falhas
- Escalabilidade independente
- Deploy independente
- Recursos computacionais dedicados

### 9.2 Estrutura
```
services/
├── getnet-service/
│   ├── src/
│   │   ├── main.ts
│   │   ├── getnet.module.ts
│   │   ├── getnet.controller.ts
│   │   ├── getnet.service.ts
│   │   ├── getnet-http.client.ts
│   │   ├── transformers/
│   │   │   ├── request.transformer.ts
│   │   │   └── response.transformer.ts
│   │   └── config/
│   │       └── getnet.config.ts
│   ├── Dockerfile
│   └── package.json
│
└── stone-service/
    ├── src/
    │   ├── main.ts
    │   ├── stone.module.ts
    │   ├── stone.controller.ts
    │   ├── stone.service.ts
    │   ├── stone-http.client.ts
    │   ├── transformers/
    │   │   ├── request.transformer.ts
    │   │   └── response.transformer.ts
    │   └── config/
    │       └── stone.config.ts
    ├── Dockerfile
    └── package.json
```

### 9.3 Benefícios
- **Isolamento**: Falha no Getnet não afeta Stone
- **Escalabilidade**: Escalar Getnet independentemente
- **Manutenção**: Atualizar um sem afetar outro
- **Recursos**: CPU/memória dedicados por gateway

---

## 10. Alta Disponibilidade e Escalabilidade

### 10.1 Multi-AZ Deployment
```yaml
# ECS Service Configuration
Service:
  ServiceName: getnet-service
  Cluster: payments-cluster
  DesiredCount: 3
  LaunchType: FARGATE
  NetworkConfiguration:
    AwsvpcConfiguration:
      Subnets:
        - subnet-1a
        - subnet-1b
        - subnet-1c
      SecurityGroups:
        - sg-getnet-service
  LoadBalancers:
    - TargetGroupArn: arn:aws:elasticloadbalancing:...
      ContainerName: getnet-service
      ContainerPort: 3000
  HealthCheckGracePeriodSeconds: 60
```

### 10.2 Auto Scaling
```json
{
  "ServiceName": "getnet-service",
  "ScalableTargetAction": {
    "MinCapacity": 2,
    "MaxCapacity": 20
  },
  "ScalingPolicies": [
    {
      "PolicyName": "cpu-scaling",
      "TargetTrackingScalingPolicyConfiguration": {
        "TargetValue": 70.0,
        "PredefinedMetricSpecification": {
          "PredefinedMetricType": "ECSServiceAverageCPUUtilization"
        }
      }
    },
    {
      "PolicyName": "request-count-scaling",
      "TargetTrackingScalingPolicyConfiguration": {
        "TargetValue": 1000.0,
        "CustomMetricSpecification": {
          "MetricName": "RequestCount",
          "Namespace": "AWS/ApplicationELB",
          "Statistic": "Sum"
        }
      }
    }
  ]
}
```

---

## 11. Monitoramento e Alertas

### 11.1 Métricas Principais
- Taxa de sucesso por gateway
- Latência P50, P95, P99
- Taxa de erro por tipo
- Circuit breaker state
- DLQ depth
- Retry count

### 11.2 Alertas
```yaml
Alerts:
  - Name: getnet-high-error-rate
    Condition: error_rate > 5%
    Duration: 5 minutes
    Severity: critical
    Actions:
      - PagerDuty
      - Slack
  
  - Name: getnet-high-latency
    Condition: p95_latency > 3000ms
    Duration: 10 minutes
    Severity: warning
    Actions:
      - Slack
  
  - Name: getnet-circuit-open
    Condition: circuit_state == 'open'
    Duration: 1 minute
    Severity: critical
    Actions:
      - PagerDuty
      - Slack
  
  - Name: payment-dlq-depth
    Condition: dlq_messages > 100
    Duration: 5 minutes
    Severity: high
    Actions:
      - PagerDuty
```

---

## 12. Disaster Recovery

### 12.1 Estratégia
- Backup de dados transacionais (RDS)
- Replicação de eventos (DocumentDB)
- Replay de eventos se necessário
- Reconciliação com gateways

### 12.2 Plano de Recuperação
1. Identificar escopo do problema
2. Ativar gateway alternativo
3. Processar DLQ
4. Reconciliar transações
5. Notificar usuários afetados
6. Gerar relatório de impacto

---

## 13. Referências

- Documento de Cenários: `0-scenarios.md`
- Documento de Mapeamento de Serviços: `1-service-map.md`
- Documento de Stack Tecnológica: `2-tech-stack.md`
- Documento de Segurança: `4-security.md`
- Documento de Observabilidade: `5-observability.md`
