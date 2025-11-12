# Documentação: Segurança da Plataforma de Pagamentos

## 1. Visão Geral

Este documento detalha a estratégia de segurança em múltiplas camadas (defense in depth) da plataforma de pagamentos, abrangendo proteção de rede, autenticação, autorização, criptografia e compliance com regulações financeiras (PCI-DSS, LGPD, BACEN).

## 2. Arquitetura de Segurança em Camadas

### 2.1 Modelo de Defesa em Profundidade
```
┌─────────────────────────────────────────────────────────┐
│              Layer 1: Edge Protection                    │
│                    (Cloudflare)                          │
│  - DDoS Protection                                       │
│  - WAF Rules                                             │
│  - Bot Management                                        │
│  - Rate Limiting                                         │
│  - Geo-blocking                                          │
└─────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────┐
│         Layer 2: AWS Network Protection                  │
│              (WAF & Shield)                              │
│  - DDoS Protection (Shield)                              │
│  - Rate-based Rules                                      │
│  - Geo Match Conditions                                  │
│  - IP Reputation Lists                                   │
└─────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────┐
│      Layer 3: Authentication & Authorization             │
│           (API Gateway + Cognito)                        │
│  - JWT Token Validation                                  │
│  - OAuth 2.0 / OIDC                                      │
│  - MFA (Multi-Factor Authentication)                     │
│  - Role-Based Access Control (RBAC)                      │
└─────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────┐
│         Layer 4: Application Security                    │
│              (Microservices)                             │
│  - Input Validation                                      │
│  - Output Encoding                                       │
│  - SQL Injection Prevention                              │
│  - XSS Prevention                                        │
│  - CSRF Protection                                       │
└─────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────┐
│           Layer 5: Data Protection                       │
│         (Encryption & Tokenization)                      │
│  - TLS/SSL (in-transit)                                  │
│  - KMS Encryption (at-rest)                              │
│  - Tokenization (PCI data)                               │
│  - Data Masking                                          │
└─────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────┐
│        Layer 6: Infrastructure Security                  │
│              (VPC & IAM)                                 │
│  - Network Segmentation                                  │
│  - Security Groups                                       │
│  - NACLs                                                 │
│  - IAM Roles & Policies                                  │
│  - Least Privilege                                       │
└─────────────────────────────────────────────────────────┘
```

## 3. Layer 1: Edge Protection (Cloudflare)

### 3.1 Cloudflare como Primeira Linha de Defesa

#### 3.1.1 Propósito
Proteger a aplicação antes mesmo de requisições chegarem à AWS, reduzindo:
- Ataques DDoS
- Tráfego malicioso
- Bots maliciosos
- Custos de infraestrutura

#### 3.1.2 Componentes

**DNS Management:**
- Proteção contra DNS amplification attacks
- DNSSEC para prevenir DNS spoofing
- Anycast network para alta disponibilidade

**Firewall Rules (Layer 1):**
```javascript
// Bloquear países de alto risco
if (ip.geoip.country in {"KP", "IR", "SY"}) {
  return "block";
}

// Bloquear IPs conhecidos por ataques
if (ip.src in $threat_intelligence_list) {
  return "block";
}

// Rate limiting por IP
if (rate(ip.src) > 100 requests per minute) {
  return "challenge";
}

// Bloquear user agents suspeitos
if (http.user_agent contains "sqlmap" or 
    http.user_agent contains "nikto") {
  return "block";
}
```

**WAF Control (Layer 1):**
```yaml
WAF_Rules:
  - Name: OWASP_Top_10
    Action: block
    Rules:
      - SQL Injection
      - XSS
      - Command Injection
      - Path Traversal
      - Remote File Inclusion
  
  - Name: API_Protection
    Action: challenge
    Rules:
      - Missing Content-Type
      - Invalid JSON
      - Oversized Payload (> 1MB)
  
  - Name: Rate_Limiting
    Action: block
    Limits:
      - 1000 req/min per IP
      - 10000 req/min per domain
```

**Bot Management:**
```yaml
Bot_Rules:
  Good_Bots:
    - Googlebot
    - Bingbot
    - Slackbot
    Action: allow
  
  Suspicious_Bots:
    - Unknown user agents
    - Headless browsers
    - Automated tools
    Action: challenge
  
  Bad_Bots:
    - Scrapers
    - Credential stuffing tools
    - DDoS tools
    Action: block
```

**Captcha:**
```yaml
Captcha_Rules:
  - Trigger: failed_login_attempts > 3
    Type: hCaptcha
    Difficulty: moderate
  
  - Trigger: suspicious_behavior
    Type: hCaptcha
    Difficulty: hard
  
  - Trigger: high_risk_country
    Type: hCaptcha
    Difficulty: moderate
```

#### 3.1.3 Configuração Avançada
```javascript
// Cloudflare Workers - Custom Logic
addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
})

async function handleRequest(request) {
  const url = new URL(request.url)
  
  // Verificar se é endpoint sensível
  if (url.pathname.startsWith('/api/v1/payments')) {
    // Aplicar validações extras
    const country = request.cf.country
    const asn = request.cf.asn
    
    // Bloquear VPNs/Proxies conhecidos
    if (isVPN(asn)) {
      return new Response('Access Denied', { status: 403 })
    }
    
    // Verificar rate limit customizado
    const rateLimitKey = `rate:${request.headers.get('cf-connecting-ip')}`
    const count = await incrementRateLimit(rateLimitKey)
    
    if (count > 50) {  // 50 req/min para pagamentos
      return new Response('Rate Limit Exceeded', { status: 429 })
    }
  }
  
  // Encaminhar para origem (AWS)
  return fetch(request)
}
```

#### 3.1.4 Métricas e Alertas
```yaml
Cloudflare_Alerts:
  - Name: high_threat_score
    Condition: threat_score > 50
    Threshold: 1000 requests
    Duration: 5 minutes
    Action: notify_security_team
  
  - Name: ddos_attack
    Condition: requests_per_second > 10000
    Duration: 1 minute
    Action: 
      - enable_under_attack_mode
      - notify_security_team
  
  - Name: high_error_rate
    Condition: error_rate > 10%
    Duration: 5 minutes
    Action: notify_devops_team
```

---

## 4. Layer 2: AWS Network Protection

### 4.1 AWS WAF

#### 4.1.1 Propósito
Segunda camada de proteção, focada em:
- Proteção específica para AWS
- Regras customizadas para a aplicação
- Integração com serviços AWS

#### 4.1.2 Configuração
```json
{
  "Name": "payments-platform-waf",
  "Scope": "REGIONAL",
  "DefaultAction": {"Allow": {}},
  "Rules": [
    {
      "Name": "rate-limit-per-ip",
      "Priority": 1,
      "Statement": {
        "RateBasedStatement": {
          "Limit": 2000,
          "AggregateKeyType": "IP",
          "ScopeDownStatement": {
            "ByteMatchStatement": {
              "SearchString": "/api/v1/",
              "FieldToMatch": {"UriPath": {}},
              "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
              "PositionalConstraint": "STARTS_WITH"
            }
          }
        }
      },
      "Action": {"Block": {}},
      "VisibilityConfig": {
        "SampledRequestsEnabled": true,
        "CloudWatchMetricsEnabled": true,
        "MetricName": "RateLimitRule"
      }
    },
    {
      "Name": "geo-blocking",
      "Priority": 2,
      "Statement": {
        "GeoMatchStatement": {
          "CountryCodes": ["KP", "IR", "SY"]
        }
      },
      "Action": {"Block": {}}
    },
    {
      "Name": "aws-managed-common-rules",
      "Priority": 3,
      "Statement": {
        "ManagedRuleGroupStatement": {
          "VendorName": "AWS",
          "Name": "AWSManagedRulesCommonRuleSet",
          "ExcludedRules": []
        }
      },
      "OverrideAction": {"None": {}}
    },
    {
      "Name": "aws-managed-known-bad-inputs",
      "Priority": 4,
      "Statement": {
        "ManagedRuleGroupStatement": {
          "VendorName": "AWS",
          "Name": "AWSManagedRulesKnownBadInputsRuleSet"
        }
      },
      "OverrideAction": {"None": {}}
    },
    {
      "Name": "aws-managed-sql-injection",
      "Priority": 5,
      "Statement": {
        "ManagedRuleGroupStatement": {
          "VendorName": "AWS",
          "Name": "AWSManagedRulesSQLiRuleSet"
        }
      },
      "OverrideAction": {"None": {}}
    },
    {
      "Name": "ip-reputation-list",
      "Priority": 6,
      "Statement": {
        "ManagedRuleGroupStatement": {
          "VendorName": "AWS",
          "Name": "AWSManagedRulesAmazonIpReputationList"
        }
      },
      "OverrideAction": {"None": {}}
    },
    {
      "Name": "custom-payment-protection",
      "Priority": 7,
      "Statement": {
        "AndStatement": {
          "Statements": [
            {
              "ByteMatchStatement": {
                "SearchString": "/api/v1/payments",
                "FieldToMatch": {"UriPath": {}},
                "TextTransformations": [{"Priority": 0, "Type": "LOWERCASE"}],
                "PositionalConstraint": "STARTS_WITH"
              }
            },
            {
              "NotStatement": {
                "Statement": {
                  "ByteMatchStatement": {
                    "SearchString": "application/json",
                    "FieldToMatch": {
                      "SingleHeader": {"Name": "content-type"}
                    },
                    "TextTransformations": [{"Priority": 0, "Type": "LOWERCASE"}],
                    "PositionalConstraint": "CONTAINS"
                  }
                }
              }
            }
          ]
        }
      },
      "Action": {"Block": {}}
    }
  ]
}
```

#### 4.1.3 Regras Customizadas
```json
{
  "Name": "block-suspicious-patterns",
  "Statement": {
    "OrStatement": {
      "Statements": [
        {
          "ByteMatchStatement": {
            "SearchString": "../",
            "FieldToMatch": {"UriPath": {}},
            "TextTransformations": [{"Priority": 0, "Type": "URL_DECODE"}],
            "PositionalConstraint": "CONTAINS"
          }
        },
        {
          "ByteMatchStatement": {
            "SearchString": "<script",
            "FieldToMatch": {"Body": {}},
            "TextTransformations": [{"Priority": 0, "Type": "HTML_ENTITY_DECODE"}],
            "PositionalConstraint": "CONTAINS"
          }
        },
        {
          "RegexMatchStatement": {
            "RegexString": "(union|select|insert|update|delete|drop).*from",
            "FieldToMatch": {"Body": {}},
            "TextTransformations": [{"Priority": 0, "Type": "LOWERCASE"}]
          }
        }
      ]
    }
  },
  "Action": {"Block": {}}
}
```

---

### 4.2 AWS Shield

#### 4.2.1 Shield Standard (Incluído)
- Proteção automática contra DDoS Layer 3/4
- Proteção para todos os recursos AWS
- Sem custo adicional

#### 4.2.2 Shield Advanced (Opcional)
```yaml
Shield_Advanced:
  Cost: $3000/month
  Benefits:
    - DDoS Response Team (DRT)
    - Cost protection (reembolso de custos de DDoS)
    - Advanced metrics e reports
    - Proteção para Layer 7
  
  Protected_Resources:
    - CloudFront distributions
    - Route53 hosted zones
    - Elastic Load Balancers
    - Elastic IPs
  
  When_to_Use:
    - High-value applications
    - Compliance requirements
    - Previous DDoS attacks
    - Need for 24/7 support
```

---

## 5. Layer 3: Authentication & Authorization

### 5.1 API Gateway + AWS Cognito

#### 5.1.1 Arquitetura de Autenticação
```
┌──────────────┐
│   Client     │
└──────┬───────┘
       │ 1. POST /auth/login
       ↓
┌──────────────────┐
│  AWS Cognito     │
│  User Pool       │
└──────┬───────────┘
       │ 2. JWT Token (access + refresh)
       ↓
┌──────────────┐
│   Client     │
└──────┬───────┘
       │ 3. GET /api/v1/payments
       │    Authorization: Bearer <token>
       ↓
┌──────────────────┐
│  API Gateway     │
│  (Authorizer)    │
└──────┬───────────┘
       │ 4. Validate JWT
       │ 5. Extract claims
       ↓
┌──────────────────┐
│  Microservice    │
│  (with user ctx) │
└──────────────────┘
```

#### 5.1.2 Cognito User Pool Configuration
```json
{
  "UserPoolName": "payments-platform-users",
  "Policies": {
    "PasswordPolicy": {
      "MinimumLength": 12,
      "RequireUppercase": true,
      "RequireLowercase": true,
      "RequireNumbers": true,
      "RequireSymbols": true,
      "TemporaryPasswordValidityDays": 7
    }
  },
  "MfaConfiguration": "OPTIONAL",
  "EnabledMfas": ["SOFTWARE_TOKEN_MFA", "SMS_MFA"],
  "AccountRecoverySetting": {
    "RecoveryMechanisms": [
      {"Name": "verified_email", "Priority": 1},
      {"Name": "verified_phone_number", "Priority": 2}
    ]
  },
  "UserAttributeUpdateSettings": {
    "AttributesRequireVerificationBeforeUpdate": ["email"]
  },
  "Schema": [
    {
      "Name": "email",
      "AttributeDataType": "String",
      "Required": true,
      "Mutable": true
    },
    {
      "Name": "phone_number",
      "AttributeDataType": "String",
      "Required": false,
      "Mutable": true
    },
    {
      "Name": "custom:user_type",
      "AttributeDataType": "String",
      "Mutable": true
    },
    {
      "Name": "custom:company_id",
      "AttributeDataType": "String",
      "Mutable": false
    },
    {
      "Name": "custom:kyc_status",
      "AttributeDataType": "String",
      "Mutable": true
    }
  ],
  "LambdaTriggers": {
    "PreSignUp": "arn:aws:lambda:...:pre-signup-validation",
    "PostConfirmation": "arn:aws:lambda:...:post-confirmation-handler",
    "PreAuthentication": "arn:aws:lambda:...:pre-auth-checks",
    "PostAuthentication": "arn:aws:lambda:...:post-auth-logging"
  }
}
```

#### 5.1.3 JWT Token Structure
```json
{
  "header": {
    "alg": "RS256",
    "kid": "abcd1234",
    "typ": "JWT"
  },
  "payload": {
    "sub": "uuid-user-id",
    "email": "user@example.com",
    "email_verified": true,
    "phone_number": "+5511999999999",
    "phone_number_verified": true,
    "custom:user_type": "customer",
    "custom:company_id": "uuid-company-id",
    "custom:kyc_status": "approved",
    "cognito:groups": ["customers", "verified_users"],
    "iss": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_xxxxx",
    "aud": "client-id",
    "token_use": "access",
    "auth_time": 1234567890,
    "iat": 1234567890,
    "exp": 1234571490
  }
}
```

#### 5.1.4 API Gateway Authorizer
```typescript
// Lambda Authorizer (Custom)
export const handler = async (event: any) => {
  const token = event.authorizationToken.replace('Bearer ', '');
  
  try {
    // Verificar token no Cognito
    const decoded = await verifyToken(token);
    
    // Verificar se usuário está ativo
    const user = await getUserFromDB(decoded.sub);
    if (!user.active) {
      throw new Error('User inactive');
    }
    
    // Verificar KYC para operações sensíveis
    if (event.methodArn.includes('/payments') && 
        decoded['custom:kyc_status'] !== 'approved') {
      throw new Error('KYC not approved');
    }
    
    // Gerar policy
    return generatePolicy(decoded.sub, 'Allow', event.methodArn, {
      userId: decoded.sub,
      email: decoded.email,
      userType: decoded['custom:user_type'],
      companyId: decoded['custom:company_id']
    });
    
  } catch (error) {
    return generatePolicy('user', 'Deny', event.methodArn);
  }
};

function generatePolicy(principalId: string, effect: string, resource: string, context?: any) {
  return {
    principalId,
    policyDocument: {
      Version: '2012-10-17',
      Statement: [{
        Action: 'execute-api:Invoke',
        Effect: effect,
        Resource: resource
      }]
    },
    context
  };
}
```

#### 5.1.5 Role-Based Access Control (RBAC)
```typescript
// RBAC Decorator
export function Roles(...roles: string[]) {
  return SetMetadata('roles', roles);
}

// RBAC Guard
@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private reflector: Reflector) {}
  
  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.get<string[]>('roles', context.getHandler());
    if (!requiredRoles) {
      return true;
    }
    
    const request = context.switchToHttp().getRequest();
    const user = request.user;
    
    return requiredRoles.some(role => user.roles?.includes(role));
  }
}

// Usage
@Controller('api/v1/admin')
@UseGuards(JwtAuthGuard, RolesGuard)
export class AdminController {
  @Get('users')
  @Roles('admin', 'support')
  async listUsers() {
    // Only admin and support can access
  }
  
  @Delete('users/:id')
  @Roles('admin')
  async deleteUser(@Param('id') id: string) {
    // Only admin can delete
  }
}
```

---

### 5.2 Multi-Factor Authentication (MFA)

#### 5.2.1 Configuração
```typescript
// Enable MFA for user
import { CognitoIdentityServiceProvider } from 'aws-sdk';

const cognito = new CognitoIdentityServiceProvider();

async function enableMFA(username: string) {
  // Set MFA preference
  await cognito.setUserMFAPreference({
    SoftwareTokenMfaSettings: {
      Enabled: true,
      PreferredMfa: true
    },
    Username: username,
    UserPoolId: process.env.COGNITO_USER_POOL_ID
  }).promise();
}

// Verify MFA token
async function verifyMFA(username: string, code: string, session: string) {
  const response = await cognito.respondToAuthChallenge({
    ChallengeName: 'SOFTWARE_TOKEN_MFA',
    ClientId: process.env.COGNITO_CLIENT_ID,
    ChallengeResponses: {
      USERNAME: username,
      SOFTWARE_TOKEN_MFA_CODE: code
    },
    Session: session
  }).promise();
  
  return response.AuthenticationResult;
}
```

#### 5.2.2 Fluxo de Login com MFA
```
1. User submits credentials
   ↓
2. Cognito validates credentials
   ↓
3. Cognito returns MFA challenge
   ↓
4. User submits MFA code
   ↓
5. Cognito validates MFA code
   ↓
6. Cognito returns JWT tokens
```

---

## 6. Layer 4: Application Security

### 6.1 Input Validation

#### 6.1.1 DTO Validation
```typescript
import { IsString, IsNumber, IsEmail, IsUUID, Min, Max, Matches } from 'class-validator';

export class CreatePaymentDto {
  @IsUUID()
  userId: string;
  
  @IsNumber()
  @Min(0.01)
  @Max(1000000)
  amount: number;
  
  @IsString()
  @Matches(/^[0-9]{16}$/)
  cardNumber: string;
  
  @IsString()
  @Matches(/^[0-9]{3,4}$/)
  cvv: string;
  
  @IsString()
  @Matches(/^(0[1-9]|1[0-2])\/[0-9]{2}$/)
  expirationDate: string;
  
  @IsEmail()
  email: string;
}

// Controller
@Post()
@UsePipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true }))
async createPayment(@Body() dto: CreatePaymentDto) {
  return this.paymentsService.create(dto);
}
```

#### 6.1.2 SQL Injection Prevention
```typescript
// NEVER do this
const query = `SELECT * FROM users WHERE email = '${email}'`;

// ALWAYS use parameterized queries (TypeORM)
const user = await this.userRepository.findOne({
  where: { email }
});

// Or query builder
const user = await this.userRepository
  .createQueryBuilder('user')
  .where('user.email = :email', { email })
  .getOne();
```

#### 6.1.3 XSS Prevention
```typescript
import * as sanitizeHtml from 'sanitize-html';

@Injectable()
export class SanitizationService {
  sanitizeInput(input: string): string {
    return sanitizeHtml(input, {
      allowedTags: [],
      allowedAttributes: {}
    });
  }
}

// Usage
@Post('comments')
async createComment(@Body() dto: CreateCommentDto) {
  dto.content = this.sanitizationService.sanitizeInput(dto.content);
  return this.commentsService.create(dto);
}
```

#### 6.1.4 CSRF Protection
```typescript
import * as csurf from 'csurf';

// Enable CSRF protection
app.use(csurf({ cookie: true }));

// Send CSRF token to client
@Get('csrf-token')
getCsrfToken(@Req() req: Request) {
  return { csrfToken: req.csrfToken() };
}

// Validate CSRF token
@Post('payment')
@UseGuards(CsrfGuard)
async createPayment(@Body() dto: CreatePaymentDto) {
  // ...
}
```

---

### 6.2 Security Headers

#### 6.2.1 Helmet Configuration
```typescript
import helmet from 'helmet';

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'", "https://api.payments-platform.com"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"]
    }
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  },
  frameguard: {
    action: 'deny'
  },
  noSniff: true,
  xssFilter: true,
  referrerPolicy: {
    policy: 'strict-origin-when-cross-origin'
  }
}));
```

---

## 7. Layer 5: Data Protection

### 7.1 TLS/SSL Encryption (In-Transit)

#### 7.1.1 AWS Certificate Manager (ACM)
```yaml
Certificate:
  DomainName: api.payments-platform.com
  SubjectAlternativeNames:
    - "*.payments-platform.com"
  ValidationMethod: DNS
  KeyAlgorithm: RSA_2048
  
TLS_Policy:
  MinimumProtocolVersion: TLSv1.2
  CipherSuites:
    - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    - TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    - TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305
```

#### 7.1.2 ALB SSL Configuration
```json
{
  "Listener": {
    "Protocol": "HTTPS",
    "Port": 443,
    "Certificates": [{
      "CertificateArn": "arn:aws:acm:us-east-1:123456789:certificate/..."
    }],
    "SslPolicy": "ELBSecurityPolicy-TLS-1-2-2017-01"
  }
}
```

---

### 7.2 Encryption at Rest (KMS)

#### 7.2.1 KMS Key Configuration
```json
{
  "KeyPolicy": {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Sid": "Enable IAM User Permissions",
        "Effect": "Allow",
        "Principal": {
          "AWS": "arn:aws:iam::123456789:root"
        },
        "Action": "kms:*",
        "Resource": "*"
      },
      {
        "Sid": "Allow services to use the key",
        "Effect": "Allow",
        "Principal": {
          "Service": [
            "rds.amazonaws.com",
            "s3.amazonaws.com",
            "secretsmanager.amazonaws.com"
          ]
        },
        "Action": [
          "kms:Decrypt",
          "kms:DescribeKey",
          "kms:CreateGrant"
        ],
        "Resource": "*"
      }
    ]
  },
  "KeySpec": "SYMMETRIC_DEFAULT",
  "KeyUsage": "ENCRYPT_DECRYPT",
  "MultiRegion": false
}
```

#### 7.2.2 RDS Encryption
```yaml
DBInstance:
  StorageEncrypted: true
  KmsKeyId: arn:aws:kms:us-east-1:123456789:key/...
  EnableIAMDatabaseAuthentication: true
```

#### 7.2.3 S3 Encryption
```json
{
  "Rules": [{
    "ApplyServerSideEncryptionByDefault": {
      "SSEAlgorithm": "aws:kms",
      "KMSMasterKeyID": "arn:aws:kms:us-east-1:123456789:key/..."
    },
    "BucketKeyEnabled": true
  }]
}
```

---

### 7.3 Tokenization (PCI Data)

#### 7.3.1 Card Tokenization
```typescript
@Injectable()
export class TokenizationService {
  constructor(
    private readonly kms: KMS,
    private readonly redis: Redis
  ) {}
  
  async tokenizeCard(cardNumber: string): Promise<string> {
    // Generate token
    const token = `tok_${uuidv4()}`;
    
    // Encrypt card number with KMS
    const encrypted = await this.kms.encrypt({
      KeyId: process.env.KMS_KEY_ID,
      Plaintext: Buffer.from(cardNumber)
    }).promise();
    
    // Store encrypted data with token as key
    await this.redis.setex(
      `token:${token}`,
      3600,  // 1 hour
      encrypted.CiphertextBlob.toString('base64')
    );
    
    return token;
  }
  
  async detokenizeCard(token: string): Promise<string> {
    // Retrieve encrypted data
    const encryptedData = await this.redis.get(`token:${token}`);
    if (!encryptedData) {
      throw new Error('Token not found or expired');
    }
    
    // Decrypt with KMS
    const decrypted = await this.kms.decrypt({
      CiphertextBlob: Buffer.from(encryptedData, 'base64')
    }).promise();
    
    return decrypted.Plaintext.toString();
  }
}
```

---

### 7.4 Data Masking

#### 7.4.1 Logging Masking
```typescript
@Injectable()
export class MaskingService {
  maskCardNumber(cardNumber: string): string {
    if (!cardNumber || cardNumber.length < 4) return '****';
    return `****-****-****-${cardNumber.slice(-4)}`;
  }
  
  maskCPF(cpf: string): string {
    if (!cpf || cpf.length < 3) return '***';
    return `***.***.***-${cpf.slice(-2)}`;
  }
  
  maskEmail(email: string): string {
    if (!email) return '***';
    const [user, domain] = email.split('@');
    return `${user.slice(0, 2)}***@${domain}`;
  }
  
  maskPhone(phone: string): string {
    if (!phone || phone.length < 4) return '****';
    return `(***) ***-${phone.slice(-4)}`;
  }
}
```

---

## 8. Layer 6: Infrastructure Security

### 8.1 VPC Network Segmentation

#### 8.1.1 VPC Architecture
```yaml
VPC:
  CIDR: 10.0.0.0/16
  
  PublicSubnets:
    - 10.0.1.0/24  (us-east-1a)
    - 10.0.2.0/24  (us-east-1b)
    - 10.0.3.0/24  (us-east-1c)
    Resources:
      - ALB
      - NAT Gateway
  
  PrivateSubnets:
    - 10.0.11.0/24 (us-east-1a)
    - 10.0.12.0/24 (us-east-1b)
    - 10.0.13.0/24 (us-east-1c)
    Resources:
      - ECS Tasks
      - Lambda Functions
  
  DatabaseSubnets:
    - 10.0.21.0/24 (us-east-1a)
    - 10.0.22.0/24 (us-east-1b)
    - 10.0.23.0/24 (us-east-1c)
    Resources:
      - RDS
      - DocumentDB
      - Redis
```

#### 8.1.2 Security Groups
```yaml
ALB_SecurityGroup:
  Ingress:
    - Port: 443
      Protocol: TCP
      Source: 0.0.0.0/0
      Description: HTTPS from internet
  Egress:
    - Port: 3000
      Protocol: TCP
      Destination: ECS_SecurityGroup
      Description: To ECS tasks

ECS_SecurityGroup:
  Ingress:
    - Port: 3000
      Protocol: TCP
      Source: ALB_SecurityGroup
      Description: From ALB
  Egress:
    - Port: 5432
      Protocol: TCP
      Destination: RDS_SecurityGroup
      Description: To PostgreSQL
    - Port: 27017
      Protocol: TCP
      Destination: DocumentDB_SecurityGroup
      Description: To DocumentDB
    - Port: 6379
      Protocol: TCP
      Destination: Redis_SecurityGroup
      Description: To Redis
    - Port: 443
      Protocol: TCP
      Destination: 0.0.0.0/0
      Description: To internet (APIs)

RDS_SecurityGroup:
  Ingress:
    - Port: 5432
      Protocol: TCP
      Source: ECS_SecurityGroup
      Description: From ECS tasks
  Egress: []

DocumentDB_SecurityGroup:
  Ingress:
    - Port: 27017
      Protocol: TCP
      Source: ECS_SecurityGroup
      Description: From ECS tasks
  Egress: []

Redis_SecurityGroup:
  Ingress:
    - Port: 6379
      Protocol: TCP
      Source: ECS_SecurityGroup
      Description: From ECS tasks
  Egress: []
```

---

### 8.2 IAM Roles & Policies

#### 8.2.1 Least Privilege Principle
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PaymentsServiceRDSAccess",
      "Effect": "Allow",
      "Action": [
        "rds-db:connect"
      ],
      "Resource": [
        "arn:aws:rds-db:us-east-1:123456789:dbuser:*/payments_user"
      ]
    },
    {
      "Sid": "PaymentsServiceS3Access",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject"
      ],
      "Resource": [
        "arn:aws:s3:::payments-platform-documents/*"
      ]
    },
    {
      "Sid": "PaymentsServiceKMSAccess",
      "Effect": "Allow",
      "Action": [
        "kms:Decrypt",
        "kms:Encrypt",
        "kms:GenerateDataKey"
      ],
      "Resource": [
        "arn:aws:kms:us-east-1:123456789:key/payments-key"
      ]
    },
    {
      "Sid": "PaymentsServiceSecretsAccess",
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue"
      ],
      "Resource": [
        "arn:aws:secretsmanager:us-east-1:123456789:secret:payments/*"
      ]
    }
  ]
}
```

---

## 9. Compliance

### 9.1 PCI-DSS

#### 9.1.1 Requisitos
- Não armazenar CVV
- Criptografar PAN (Primary Account Number)
- Tokenização de dados de cartão
- Logs de auditoria
- Controle de acesso
- Testes de segurança regulares

#### 9.1.2 Implementação
```typescript
@Injectable()
export class PCIComplianceService {
  async processCardData(cardData: CardData): Promise<TokenizedCard> {
    // NEVER log card data
    this.logger.info({ action: 'card.processing' });
    
    // Validate card
    if (!this.validateCard(cardData)) {
      throw new InvalidCardException();
    }
    
    // Tokenize immediately
    const token = await this.tokenizationService.tokenizeCard(
      cardData.cardNumber
    );
    
    // NEVER store CVV
    // Use CVV only for authorization, then discard
    
    return {
      token,
      last4: cardData.cardNumber.slice(-4),
      brand: cardData.brand,
      expirationDate: cardData.expirationDate
    };
  }
}
```

---

### 9.2 LGPD (Lei Geral de Proteção de Dados)

#### 9.2.1 Requisitos
- Consentimento explícito
- Direito ao esquecimento
- Portabilidade de dados
- Anonimização de logs
- Data retention policies

#### 9.2.2 Implementação
```typescript
@Injectable()
export class LGPDComplianceService {
  async requestDataDeletion(userId: string): Promise<void> {
    // Anonimizar dados pessoais
    await this.userRepository.update(userId, {
      email: `deleted_${userId}@anonymized.com`,
      phone: null,
      cpf: null,
      name: 'Deleted User',
      deletedAt: new Date()
    });
    
    // Manter dados financeiros por período legal (5 anos)
    // mas anonimizados
    await this.paymentsRepository.update(
      { userId },
      { userDataAnonymized: true }
    );
    
    // Log da ação
    await this.auditService.log({
      action: 'user.data.deleted',
      userId,
      timestamp: new Date()
    });
  }
  
  async exportUserData(userId: string): Promise<any> {
    // Coletar todos os dados do usuário
    const user = await this.userRepository.findOne(userId);
    const payments = await this.paymentsRepository.find({ userId });
    const transfers = await this.transfersRepository.find({ userId });
    
    return {
      personalData: user,
      financialData: {
        payments,
        transfers
      },
      exportedAt: new Date()
    };
  }
}
```

---

## 10. Security Monitoring

### 10.1 CloudWatch Alarms
```yaml
Alarms:
  - Name: high-failed-login-attempts
    Metric: FailedLoginAttempts
    Threshold: 10
    Period: 5 minutes
    Action: notify_security_team
  
  - Name: unusual-api-calls
    Metric: APICallCount
    Threshold: 10000
    Period: 1 minute
    Action: trigger_investigation
  
  - Name: unauthorized-access-attempts
    Metric: 401Responses
    Threshold: 100
    Period: 5 minutes
    Action: notify_security_team
```

---

## 11. Referências

- Documento de Cenários: `0-scenarios.md`
- Documento de Stack Tecnológica: `2-tech-stack.md`
- Documento de Estratégia de Integração: `3-integration-stratefy.md`
- Documento de Observabilidade: `5-observability.md`
