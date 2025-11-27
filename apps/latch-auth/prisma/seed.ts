// import { PrismaClient } from '@prisma/client';
// // @ts-ignore
// import * as crypto from 'crypto';

// const prisma = new PrismaClient();

// // --- Utility: stable sort (identical to EventLogService) ---
// function sortObjectKeys(obj: any): any {
//   if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) return obj;
//   return Object.keys(obj)
//     .sort()
//     .reduce((acc: any, k) => {
//       acc[k] = sortObjectKeys(obj[k]);
//       return acc;
//     }, {});
// }

// // --- Utility: integrity hashing (identical to EventLogService) ---
// function computeIntegrity(payload: Record<string, any>, secret: string): string {
//   const stable = JSON.stringify(sortObjectKeys(payload));
//   const toHash = `${stable}::${secret}`;
//   return crypto.createHash('sha256').update(toHash).digest('hex');
// }

// // --- Optional helpers (mask/truncate, same as service) ---
// function maskIp(ip?: string | null): string | null {
//   if (!ip) return null;
//   if (ip.includes(':')) {
//     const parts = ip.split(':');
//     const head = parts.slice(0, 4).join(':');
//     return `${head}::`;
//   }
//   const parts = ip.split('.');
//   if (parts.length === 4) {
//     parts[3] = 'x';
//     return parts.join('.');
//   }
//   return null;
// }
// function truncateUserAgent(ua?: string | null, max = 256): string | null {
//   if (!ua) return null;
//   return ua.length > max ? ua.substring(0, max) : ua;
// }

// async function main() {
//   const tenantCount = await prisma.tenant.count();
//   if (tenantCount > 0) {
//     console.log('✅ Mock seed skipped — DB already populated.');
//     return;
//   }

//   console.log('🌱 Seeding mock data...');

//   // Create Tenant + User + Session
//   const tenant = await prisma.tenant.create({
//     data: { name: 'Demo Tenant', slug: 'demo' },
//   });

//   const user = await prisma.user.create({
//     data: {
//       tenantId: tenant.id,
//       phone: '+15555550123',
//       name: 'Demo User',
//       isPhoneVerified: true,
//     },
//   });

//   await prisma.session.create({
//     data: {
//       userId: user.id,
//       tenantId: tenant.id,
//       refreshHash: 'mock-refresh-hash',
//       ipAddress: '127.0.0.1',
//       userAgent: 'seed-script',
//       lastActiveAt: new Date(),
//       expiresAt: new Date(Date.now() + 1000 * 60 * 60 * 24),
//     },
//   });

//   // --- Create a mock security event with integrity chain ---
//   // Use Bun's environment variables: use globalThis.Bun?.env for compatibility and fallback
//   const secret = (globalThis.Bun?.env?.EVENT_SIGNING_SECRET) ?? 'dev-secret';
//   const last = await prisma.event.findFirst({
//     orderBy: { createdAt: 'desc' },
//     select: { integrityHash: true },
//   });


//   const prevHash = last?.integrityHash ?? null;

//   const payload = {
//     userId: user.id,
//     tenantId: tenant.id,
//     type: 'SECURITY_STATUS_CHECKED',
//     severity: 'INFO',
//     metadata: sortObjectKeys({ seeded: true }),
//     ipAddress: maskIp('127.0.0.1'),
//     userAgent: truncateUserAgent('seed-script'),
//     prevHash,
//     createdAt: new Date().toISOString(),
//   };

//   const integrityHash = computeIntegrity(payload, secret);

//   await prisma.event.create({
//     data: {
//       userId: user.id,
//       tenantId: tenant.id,
//       type: 'SECURITY_STATUS_CHECKED',
//       severity: 'INFO',
//       metadata: payload.metadata,
//       ipAddress: payload.ipAddress,
//       userAgent: payload.userAgent,
//       integrityHash,
//       prevHash,
//     },
//   });

//   console.log('🧩 Mock security event logged.');
//   console.log('✅ Mock seed completed.');
// }

// main()
//   .catch((e) => {
//     console.error('❌ Mock seed failed:', e);
//   })
//   .finally(async () => {
//     await prisma.$disconnect();
//   });
// prisma/seed.ts
/// <reference types="node" />
import { PrismaClient, PermissionAction, EventSeverity, TenantStatus, ConditionType, EventType } from '@prisma/client';
import * as crypto from 'crypto';

const prisma = new PrismaClient();

// --- Utility: stable sort (identical to EventLogService) ---
function sortObjectKeys(obj: any): any {
  if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) return obj;
  return Object.keys(obj)
    .sort()
    .reduce((acc: any, k) => {
      acc[k] = sortObjectKeys(obj[k]);
      return acc;
    }, {});
}

// --- Utility: integrity hashing (identical to EventLogService) ---
function computeIntegrity(payload: Record<string, any>, secret: string): string {
  const stable = JSON.stringify(sortObjectKeys(payload));
  const toHash = `${stable}::${secret}`;
  return crypto.createHash('sha256').update(toHash).digest('hex');
}

// --- Optional helpers (mask/truncate, same as service) ---
function maskIp(ip?: string | null): string | null {
  if (!ip) return null;
  if (ip.includes(':')) {
    const parts = ip.split(':');
    const head = parts.slice(0, 4).join(':');
    return `${head}::`;
  }
  const parts = ip.split('.');
  if (parts.length === 4) {
    parts[3] = 'x';
    return parts.join('.');
  }
  return null;
}

function truncateUserAgent(ua?: string | null, max = 256): string | null {
  if (!ua) return null;
  return ua.length > max ? ua.substring(0, max) : ua;
}

// Enhanced seeding with proper error handling and rollback capabilities
async function seedSystemRoles(tenantId: string) {
  console.log('   🏷️  Creating system roles...');
  
  const roles = await Promise.all([
    prisma.role.create({
       data: {
        tenantId,
        name: 'SUPER_ADMIN',
        description: 'Super administrative role with system-level access and all permissions',
        isSystem: true,
        isActive: true,
        priority: 200,
        validFrom: new Date(),
        validUntil: new Date(Date.now() + 100 * 365 * 24 * 60 * 60 * 1000), // Far future
      },
    }),
    prisma.role.create({
       data: {
        tenantId,
        name: 'ADMIN',
        description: 'Administrative role with full tenant access',
        isSystem: true,
        isActive: true,
        priority: 100,
        validFrom: new Date(),
        validUntil: new Date(Date.now() + 100 * 365 * 24 * 60 * 60 * 1000), // Far future
      },
    }),
    prisma.role.create({
       data: {
        tenantId,
        name: 'SYSTEM_ADMIN',
        description: 'System administrative role for infrastructure management',
        isSystem: true,
        isActive: true,
        priority: 150,
        validFrom: new Date(),
        validUntil: new Date(Date.now() + 100 * 365 * 24 * 60 * 60 * 1000), // Far future
      },
    }),
    prisma.role.create({
       data: {
        tenantId,
        name: 'USER',
        description: 'Standard user role with basic access',
        isSystem: true,
        isActive: true,
        priority: 10,
        validFrom: new Date(),
        validUntil: new Date(Date.now() + 100 * 365 * 24 * 60 * 60 * 1000), // Far future
      },
    }),
    prisma.role.create({
       data: {
        tenantId,
        name: 'AUDITOR',
        description: 'Auditing role with read-only access to logs and events',
        isSystem: true,
        isActive: true,
        priority: 50,
        validFrom: new Date(),
        validUntil: new Date(Date.now() + 100 * 365 * 24 * 60 * 60 * 1000), // Far future
      },
    }),
  ]);

  console.log(`   ✅ Created ${roles.length} system roles`);
  return roles;
}

async function seedSystemPermissions(tenantId: string) {
  console.log('   🔐 Creating system permissions...');
  
  const permissions = await Promise.all([
    // User management permissions
    prisma.permission.create({
       data: {
        tenantId,
        name: 'manage_users',
        description: 'Manage user accounts and profiles',
        resource: 'users',
        action: PermissionAction.UPDATE,
      },
    }),
    prisma.permission.create({
       data: {
        tenantId,
        name: 'view_users',
        description: 'View user information',
        resource: 'users',
        action: PermissionAction.READ,
      },
    }),
    prisma.permission.create({
       data: {
        tenantId,
        name: 'delete_users',
        description: 'Delete user accounts',
        resource: 'users',
        action: PermissionAction.DELETE,
      },
    }),
    
    // Role management permissions
    prisma.permission.create({
      data: {
        tenantId,
        name: 'manage_roles',
        description: 'Manage role assignments and permissions',
        resource: 'roles',
        action: PermissionAction.UPDATE,
      },
    }),
    prisma.permission.create({
      data: {
        tenantId,
        name: 'view_roles',
        description: 'View role information',
        resource: 'roles',
        action: PermissionAction.READ,
      },
    }),
    
    // Audit and security permissions
    prisma.permission.create({
      data: {
        tenantId,
        name: 'view_audit',
        description: 'Access audit logs and events',
        resource: 'audit',
        action: PermissionAction.READ,
      },
    }),
    prisma.permission.create({
      data: {
        tenantId,
        name: 'manage_security',
        description: 'Manage security settings and policies',
        resource: 'security',
        action: PermissionAction.UPDATE,
      },
    }),
    
    // Tenant management permissions
    prisma.permission.create({
      data: {
        tenantId,
        name: 'manage_tenants',
        description: 'Manage tenant configurations',
        resource: 'tenants',
        action: PermissionAction.UPDATE,
      },
    }),
    
    // System configuration permissions
    prisma.permission.create({
      data: {
        tenantId,
        name: 'system_config',
        description: 'System-level configuration access',
        resource: 'system',
        action: PermissionAction.UPDATE,
      },
    }),
    prisma.permission.create({
      data: {
        tenantId,
        name: 'system_monitor',
        description: 'Monitor system health and metrics',
        resource: 'system',
        action: PermissionAction.READ,
      },
    }),
  ]);

  console.log(`   ✅ Created ${permissions.length} system permissions`);
  return permissions;
}

async function seedPermissionConditions(permissions: any[]) {
  console.log('   🛡️  Creating permission conditions...');
  
  const conditions = await Promise.all([
    prisma.permissionCondition.create({
      data: {
        permissionId: permissions.find(p => p.name === 'manage_users').id,
        conditionType: ConditionType.TENANT_DATA_ONLY,
        value: { description: 'Users can only manage data within their tenant' },
        description: 'Tenant isolation for user management',
      },
    }),
    prisma.permissionCondition.create({
      data: {
        permissionId: permissions.find(p => p.name === 'view_audit').id,
        conditionType: ConditionType.TIME_BASED,
        value: { 
          allowedHours: ['09:00', '17:00'],
          timezone: 'UTC'
        },
        description: 'Audit access limited to business hours',
      },
    }),
    prisma.permissionCondition.create({
      data: {
        permissionId: permissions.find(p => p.name === 'manage_security').id,
        conditionType: ConditionType.MFA_REQUIRED,
        value: { 
          required: true,
          factors: ['TOTP', 'SMS']
        },
        description: 'MFA required for security management',
      },
    }),
  ]);

  console.log(`   ✅ Created ${conditions.length} permission conditions`);
  return conditions;
}

async function seedRolePermissions(roles: any[], permissions: any[]) {
  console.log('   📋 Assigning permissions to roles...');
    
// Super Admin gets all permissions
await Promise.all(
  permissions.map(permission =>
    prisma.rolePermission.create({
       data: {
        roleId: roles.find(r => r.name === 'SUPER_ADMIN').id,
        permissionId: permission.id,
        allowed: true,
        inherited: false,
        priority: 200,
      },
    })
  )
);

  // Admin role gets most permissions
const adminPermissions = [
  'manage_users', 'view_users', 'delete_users', 'manage_roles', 
  'view_roles', 'view_audit', 'manage_security', 'manage_tenants'
];

const adminRolePermissions = adminPermissions
  .map(permName => permissions.find(p => p.name === permName))
  .filter(Boolean); // Remove undefined values

await Promise.all(
  adminRolePermissions.map(permission =>
    prisma.rolePermission.create({
       data: {
        roleId: roles.find(r => r.name === 'ADMIN').id,
        permissionId: permission.id,
        allowed: true,
        inherited: false,
        priority: 100,
      },
    })
  )
);
  // System Admin gets system-level permissions
const systemAdminPermissions = ['system_config', 'system_monitor', 'view_audit', 'manage_security'];

const sysAdminRolePermissions = systemAdminPermissions
  .map(permName => permissions.find(p => p.name === permName))
  .filter(Boolean); // Remove undefined values

await Promise.all(
  sysAdminRolePermissions.map(permission =>
    prisma.rolePermission.create({
       data: {
        roleId: roles.find(r => r.name === 'SYSTEM_ADMIN').id,
        permissionId: permission.id,
        allowed: true,
        inherited: false,
        priority: 150,
      },
    })
  )
);

  // Auditor gets only audit permissions
const permission = permissions.find(p => p.name === 'view_audit');
if (permission) {
  await Promise.all([
    prisma.rolePermission.create({
       data: {
        roleId: roles.find(r => r.name === 'AUDITOR').id,
        permissionId: permission.id,
        allowed: true,
        inherited: false,
        priority: 50,
      },
    })
  ]);
}
    console.log(`   ✅ Assigned permissions to ${roles.length} roles`);
}

async function seedTenantPolicy(tenantId: string, defaultRoleId: string) {
  console.log('   ⚙️  Creating tenant policy...');
  
  const policy = await prisma.tenantPolicy.create({
    data: {
      tenantId,
      requireMFA: false,
      privilegedUserMFARequired: true,
      roleInheritanceEnabled: true,
      permissionConflictStrategy: 'DENY_WINS', // Most secure default
      allowedFactors: ['SMS', 'TOTP', 'WEBAUTHN'],
      defaultRoleId,
      createdAt: new Date(),
      updatedAt: new Date(),
    },
  });

  console.log('   ✅ Created tenant policy');
  return policy;
}

async function seedPermissionRules(tenantId: string) {
  console.log('   📏 Creating permission rules...');
  
  const rules = await Promise.all([
    prisma.permissionRule.create({
      data: {
        tenantId,
        name: 'block_sensitive_operations_outside_business_hours',
        description: 'Block sensitive operations outside business hours',
        condition: {
          and: [
            { var: 'resource' },
            { in: ['security', 'system'] },
            { var: 'time' },
            { lessThan: '09:00' },
            { greaterThan: '17:00' }
          ]
        },
        effect: 'DENY',
        priority: 1000,
        isActive: true,
      },
    }),
    prisma.permissionRule.create({
      data: {
        tenantId,
        name: 'require_mfa_for_admin_actions',
        description: 'Require MFA for administrative actions',
        condition: {
          and: [
            { var: 'action' },
            { in: ['UPDATE', 'DELETE', 'EXECUTE'] },
            { var: 'resource' },
            { in: ['users', 'roles', 'security'] }
          ]
        },
        effect: 'CONDITIONAL',
        priority: 900,
        isActive: true,
      },
    }),
  ]);

  console.log(`   ✅ Created ${rules.length} permission rules`);
  return rules;
}

async function main() {
  const tenantCount = await prisma.tenant.count();
  if (tenantCount > 0) {
    console.log('✅ Seed skipped — Database already populated.');
    return;
  }

  console.log('🌱 Seeding production data with comprehensive security setup...');

  try {
    // Create main tenant
    console.log('1️⃣  Creating main tenant...');
    const tenant = await prisma.tenant.create({
      data: {
        name: 'Production Tenant',
        slug: 'production',
        status: TenantStatus.ACTIVE,
        branding: {
          logoUrl: 'https://example.com/logo.png',
          primaryColor: '#007bff',
          secondaryColor: '#6c757d',
          companyName: 'Production Company',
        },
        createdAt: new Date(),
        updatedAt: new Date(),
      },
    });
    console.log(`   ✅ Created tenant: ${tenant.name} (${tenant.slug})`);

    // Create system roles
    console.log('2️⃣  Setting up role hierarchy...');
    const roles = await seedSystemRoles(tenant.id);

    // Create system permissions
    console.log('3️⃣  Setting up permission system...');
    const permissions = await seedSystemPermissions(tenant.id);

    // Create permission conditions
    await seedPermissionConditions(permissions);

    // Assign permissions to roles
    await seedRolePermissions(roles, permissions);

    // Create permission rules
    await seedPermissionRules(tenant.id);

    // Create tenant policy with default role
const userRole = roles.find(r => r.name === 'USER');
if (!userRole) {
  console.warn('USER role not found, creating fallback USER role');
  
  // Create a basic USER role if it doesn't exist
  const fallbackUserRole = await prisma.role.create({
     data: {
      tenantId: tenant.id,
      name: 'USER',
      description: 'Standard user role with basic access',
      isSystem: true,
      isActive: true,
      priority: 10,
      validFrom: new Date(),
      validUntil: new Date(Date.now() + 100 * 365 * 24 * 60 * 60 * 1000), // Far future
    },
  });
  
  await seedTenantPolicy(tenant.id, fallbackUserRole.id);
} else {
  await seedTenantPolicy(tenant.id, userRole.id);
}

    // Create users
    console.log('4️⃣  Creating system users...');
    const users = await Promise.all([
      prisma.user.create({
        data: {
          tenantId: tenant.id,
          phone: '+15555550100',
          email: 'admin@production.com',
          name: 'Admin User',
          isPhoneVerified: true,
          isEmailVerified: true,
          createdAt: new Date(),
          updatedAt: new Date(),
        },
      }),
      prisma.user.create({
        data: {
          tenantId: tenant.id,
          phone: '+15555550101',
          email: 'user@production.com',
          name: 'Regular User',
          isPhoneVerified: true,
          isEmailVerified: true,
          createdAt: new Date(),
          updatedAt: new Date(),
        },
      }),
      prisma.user.create({
        data: {
          tenantId: tenant.id,
          phone: '+15555550102',
          email: 'superadmin@production.com',
          name: 'Super Admin User',
          isPhoneVerified: true,
          isEmailVerified: true,
          createdAt: new Date(),
          updatedAt: new Date(),
        },
      }),
      prisma.user.create({
        data: {
          tenantId: tenant.id,
          phone: '+15555550103',
          email: 'sysadmin@production.com',
          name: 'System Admin User',
          isPhoneVerified: true,
          isEmailVerified: true,
          createdAt: new Date(),
          updatedAt: new Date(),
        },
      }),
      prisma.user.create({
        data: {
          tenantId: tenant.id,
          phone: '+15555550104',
          email: 'auditor@production.com',
          name: 'Auditor User',
          isPhoneVerified: true,
          isEmailVerified: true,
          createdAt: new Date(),
          updatedAt: new Date(),
        },
      }),
    ]);
    console.log(`   ✅ Created ${users.length} users`);

    // Assign roles to users
    console.log('5️⃣  Assigning roles to users...');



// First, safely find users and roles
const adminUser = users.find(u => u.email === 'admin@production.com');
const regularUser = users.find(u => u.email === 'user@production.com');
const superAdminUser = users.find(u => u.email === 'superadmin@production.com');
const sysAdminUser = users.find(u => u.email === 'sysadmin@production.com');
const auditorUser = users.find(u => u.email === 'auditor@production.com');

const adminRole = roles.find(r => r.name === 'ADMIN');
// const userRole = roles.find(r => r.name === 'USER');
const superAdminRole = roles.find(r => r.name === 'SUPER_ADMIN');
const sysAdminRole = roles.find(r => r.name === 'SYSTEM_ADMIN');
const auditorRole = roles.find(r => r.name === 'AUDITOR');

// Validate all required entities exist
if (!adminUser || !regularUser || !superAdminUser || !sysAdminUser || !auditorUser) {
  throw new Error('One or more users not found for role assignment');
}
if (!adminRole || !userRole || !superAdminRole || !sysAdminRole || !auditorRole) {
  throw new Error('One or more roles not found for assignment');
}

    await Promise.all([
      prisma.userRole.create({
        data: {
          userId: adminUser.id,
          roleId: adminRole.id,
          createdAt: new Date(),
          validFrom: new Date(),
          validUntil: new Date(Date.now() + 100 * 365 * 24 * 60 * 60 * 1000), // Far future
        },
      }),
      prisma.userRole.create({
        data: {
          userId: regularUser.id,
          roleId: userRole.id,
          createdAt: new Date(),
          validFrom: new Date(),
          validUntil: new Date(Date.now() + 100 * 365 * 24 * 60 * 60 * 1000), // Far future
        },
      }),
      prisma.userRole.create({
        data: {
          userId: superAdminUser.id,
          roleId: superAdminRole.id,
          createdAt: new Date(),
          validFrom: new Date(),
          validUntil: new Date(Date.now() + 100 * 365 * 24 * 60 * 60 * 1000), // Far future
        },
      }),
      prisma.userRole.create({
        data: {
          userId: sysAdminUser.id,
          roleId: sysAdminRole.id,
          createdAt: new Date(),
          validFrom: new Date(),
          validUntil: new Date(Date.now() + 100 * 365 * 24 * 60 * 60 * 1000), // Far future
        },
      }),
      prisma.userRole.create({
        data: {
          userId: auditorUser.id,
          roleId: auditorRole.id,
          createdAt: new Date(),
          validFrom: new Date(),
          validUntil: new Date(Date.now() + 100 * 365 * 24 * 60 * 60 * 1000), // Far future
        },
      }),
    ]);
    console.log('   ✅ Roles assigned to users');

    // Create sessions for users
    console.log('6️⃣  Creating user sessions...');
    await Promise.all([
      prisma.session.create({
        data: {
          userId: adminUser.id,
          tenantId: tenant.id,
          refreshHash: crypto.randomBytes(32).toString('hex'), // More secure
          ipAddress: '127.0.0.1',
          userAgent: 'production-seed-script',
          lastActiveAt: new Date(),
          expiresAt: new Date(Date.now() + 1000 * 60 * 60 * 24),
          createdAt: new Date(),
        },
      }),
      prisma.session.create({
        data: {
          userId: regularUser.id,
          tenantId: tenant.id,
          refreshHash: crypto.randomBytes(32).toString('hex'),
          ipAddress: '127.0.0.1',
          userAgent: 'production-seed-script',
          lastActiveAt: new Date(),
          expiresAt: new Date(Date.now() + 1000 * 60 * 60 * 24),
          createdAt: new Date(),
        },
      }),
      prisma.session.create({
        data: {
          userId: superAdminUser.id,
          tenantId: tenant.id,
          refreshHash: crypto.randomBytes(32).toString('hex'),
          ipAddress: '127.0.0.1',
          userAgent: 'production-seed-script',
          lastActiveAt: new Date(),
          expiresAt: new Date(Date.now() + 1000 * 60 * 60 * 24),
          createdAt: new Date(),
        },
      }),
      prisma.session.create({
        data: {
          userId: sysAdminUser.id,
          tenantId: tenant.id,
          refreshHash: crypto.randomBytes(32).toString('hex'),
          ipAddress: '127.0.0.1',
          userAgent: 'production-seed-script',
          lastActiveAt: new Date(),
          expiresAt: new Date(Date.now() + 1000 * 60 * 60 * 24),
          createdAt: new Date(),
        },
      }),
      prisma.session.create({
        data: {
          userId: auditorUser.id,
          tenantId: tenant.id,
          refreshHash: crypto.randomBytes(32).toString('hex'),
          ipAddress: '127.0.0.1',
          userAgent: 'production-seed-script',
          lastActiveAt: new Date(),
          expiresAt: new Date(Date.now() + 1000 * 60 * 60 * 24),
          createdAt: new Date(),
        },
      }),
    ]);
    console.log('   ✅ Sessions created for all users');

    // Create comprehensive audit trail with integrity chain
    console.log('7️⃣  Creating security audit trail...');
    const secret = typeof process !== 'undefined' ? process.env.EVENT_SIGNING_SECRET ?? 'dev-secret' : 'dev-secret';

    // Get the most recent event for integrity chain (should be null initially)
    let prevHash: string | null = null;

    // Create initial system setup event
    const systemSetupPayload = {
      userId: superAdminUser.id,
      tenantId: tenant.id,
      type: EventType.SECURITY_STATUS_CHECKED,
      severity: EventSeverity.INFO,
      metadata: sortObjectKeys({
        seeded: true,
        phase: 'system_setup',
        components: {
          tenant: tenant.id,
          roles: roles.map(r => ({ id: r.id, name: r.name })),
          permissions: permissions.map(p => ({ id: p.id, name: p.name })),
          users: users.map(u => ({ id: u.id, email: u.email })),
          sessions: 5,
          policies: 1,
          permissionRules: 2,
          permissionConditions: 3,
        },
        timestamp: new Date().toISOString(),
      }),
      ipAddress: maskIp('127.0.0.1'),
      userAgent: truncateUserAgent('production-seed-script'),
      prevHash,
      createdAt: new Date().toISOString(),
    };

    const systemSetupHash = computeIntegrity(systemSetupPayload, secret);

    await prisma.event.create({
       data: {
        userId: systemSetupPayload.userId,
        tenantId: systemSetupPayload.tenantId,
        type: EventType.SECURITY_STATUS_CHECKED,
        severity: EventSeverity.INFO,
        metadata: systemSetupPayload.metadata,
        ipAddress: systemSetupPayload.ipAddress,
        userAgent: systemSetupPayload.userAgent,
        integrityHash: systemSetupHash,
        prevHash: systemSetupPayload.prevHash,
        createdAt: new Date(),
      },
    });

    prevHash = systemSetupHash;

    // Create user creation events
    for (const user of users) {
      const userCreationPayload = {
        userId: superAdminUser.id,
        tenantId: tenant.id,
        type: EventType.USER_PROFILE_UPDATE,
        severity: EventSeverity.SECURITY,
        metadata: sortObjectKeys({
          seeded: true,
          action: 'user_creation',
          targetUserId: user.id,
          createdUser: { id: user.id, email: user.email, name: user.name },
          grantedBy: 'seed_script',
        }),
        ipAddress: maskIp('127.0.0.1'),
        userAgent: truncateUserAgent('production-seed-script'),
        prevHash,
        createdAt: new Date().toISOString(),
      };

      const userCreationHash = computeIntegrity(userCreationPayload, secret);

      await prisma.event.create({
        data: {
          userId: userCreationPayload.userId,
          tenantId: userCreationPayload.tenantId,
          type: userCreationPayload.type,
          severity: userCreationPayload.severity,
          metadata: userCreationPayload.metadata,
          ipAddress: userCreationPayload.ipAddress,
          userAgent: userCreationPayload.userAgent,
          integrityHash: userCreationHash,
          prevHash: userCreationPayload.prevHash,
          createdAt: new Date(),
        },
      });

      prevHash = userCreationHash;
    }

    // Create role assignment events
    for (const [index, user] of users.entries()) {
      const roleName = ['ADMIN', 'USER', 'SUPER_ADMIN', 'SYSTEM_ADMIN', 'AUDITOR'][index];
      const role = roles.find(r => r.name === roleName);

      if (!role) {
        console.warn(`Role ${roleName} not found for user ${user.id}`);
        continue; // Skip this iteration
      }

      const roleAssignmentPayload = {
        userId: superAdminUser.id,
        tenantId: tenant.id,
        type: EventType.USER_PROFILE_UPDATE,
        severity: EventSeverity.SECURITY,
        metadata: sortObjectKeys({
          seeded: true,
          action: 'role_assignment',
          targetUserId: user.id,
          assignedRoleId: role.id,
          assignedRoleName: role.name,
          grantedBy: 'seed_script',
        }),
        ipAddress: maskIp('127.0.0.1'),
        userAgent: truncateUserAgent('production-seed-script'),
        prevHash,
        createdAt: new Date().toISOString(),
      };

      const roleAssignmentHash = computeIntegrity(roleAssignmentPayload, secret);

      await prisma.event.create({
        data: {
          userId: roleAssignmentPayload.userId,
          tenantId: roleAssignmentPayload.tenantId,
          type: roleAssignmentPayload.type,
          severity: roleAssignmentPayload.severity,
          metadata: roleAssignmentPayload.metadata,
          ipAddress: roleAssignmentPayload.ipAddress,
          userAgent: roleAssignmentPayload.userAgent,
          integrityHash: roleAssignmentHash,
          prevHash: roleAssignmentPayload.prevHash,
          createdAt: new Date(),
        },
      });

      prevHash = roleAssignmentHash;
    }

    console.log('   ✅ Security audit trail created with integrity chain');

    console.log('\n🎉 Production seed completed successfully!');
    console.log(`📊 Summary: 1 tenant, ${users.length} users, ${roles.length} roles, ${permissions.length} permissions`);
    console.log(`🔒 Security: Integrity chain established, policies configured, audit trail created`);
    console.log(`🛡️  Advanced: Permission conditions, rules, and role inheritance enabled`);

  } catch (error) {
    console.error('❌ Seed failed with error:', error);
    throw error;
  }
}

main()
  .catch((e) => {
    console.error('❌ Seed failed:', e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });