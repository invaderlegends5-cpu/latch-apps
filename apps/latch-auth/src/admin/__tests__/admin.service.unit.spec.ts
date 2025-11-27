//admin.service.unit.spec.ts
import { Test, TestingModule } from '@nestjs/testing';
import { AdminService } from '../admin.service';
import { PrismaService } from '@/prisma/prisma.service';
import { EventLogService } from '@/events/event.service';
import { BadRequestException, NotFoundException, ForbiddenException } from '@nestjs/common';
import { Redis } from 'ioredis';
import { UpdateUserRoleDto, UserRoleOperation } from '../dto/update-user-role.dto';

describe('AdminService', () => {
  let service: AdminService;
  let prisma: PrismaService;
  let eventLog: EventLogService;
  let redis: Redis;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AdminService,
        {
          provide: PrismaService,
          useValue: {
            user: {
              findMany: jest.fn(),
              count: jest.fn(),
              findUnique: jest.fn(),
              update: jest.fn(),
            },
            userRole: {
              findMany: jest.fn(),
              create: jest.fn(),
              deleteMany: jest.fn(),
              findUnique: jest.fn(),
              aggregate: jest.fn(),
            },
            role: {
              findMany: jest.fn(),
              findUnique: jest.fn(),
              groupBy: jest.fn(),
              aggregate: jest.fn(),
            },
            event: {
              count: jest.fn(),
            },
            tenant: {
              findUnique: jest.fn(),
            },
            rolePermission: { // Add this for getRoleAnalytics
                aggregate: jest.fn(),
              },
            $transaction: jest.fn(),
          },
        },
        {
          provide: EventLogService,
          useValue: {
            logEvent: jest.fn(),
            queryEvents: jest.fn(),
          },
        },
        {
          provide: 'REDIS',
          useValue: {
            get: jest.fn(),
            setex: jest.fn(),
            del: jest.fn(),
          },
        },
      ],
    }).compile();

    service = module.get<AdminService>(AdminService);
    prisma = module.get<PrismaService>(PrismaService);
    eventLog = module.get<EventLogService>(EventLogService);
    redis = module.get<Redis>('REDIS');
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('findAllUsers', () => {
    it('should return paginated users with role details', async () => {
      const mockUsers = [
        {
          id: 'user-id',
          name: 'Test User',
          email: 'test@example.com',
          phone: '1234567890',
          tenantId: 'tenant-id',
          createdAt: new Date(),
          updatedAt: new Date(),
          isPhoneVerified: true,
          isEmailVerified: true,
          tenant: { id: 'tenant-id', name: 'Test Tenant', slug: 'test-tenant' },
          roles: [
            {
              role: {
                id: 'role-id',
                name: 'Admin',
                description: 'Admin role',
                isSystem: false,
                isActive: true,
                validFrom: new Date(),
                validUntil: new Date(Date.now() + 1000 * 60 * 60 * 24),
              },
            },
          ],
        },
      ];

      const mockTenant = { id: 'tenant-id' };

      jest.spyOn(redis, 'get').mockResolvedValue(null);
      jest.spyOn(prisma.tenant, 'findUnique').mockResolvedValue(mockTenant);
      jest.spyOn(prisma.user, 'findMany').mockResolvedValue(mockUsers);
      jest.spyOn(prisma.user, 'count').mockResolvedValue(1);

      const result = await service.findAllUsers(50, 0, 'tenant-id', true, 'search', 'active');

      expect(prisma.user.findMany).toHaveBeenCalledWith({
        where: expect.objectContaining({
          tenantId: 'tenant-id',
          OR: expect.any(Array),
        }),
        skip: 0,
        take: 50,
        orderBy: { createdAt: 'desc' },
        include: expect.objectContaining({
          tenant: expect.any(Object),
          roles: expect.objectContaining({
            include: expect.any(Object),
            where: undefined, // because includeRoleDetails is true
          }),
        }),
      });
      expect(redis.setex).toHaveBeenCalledWith(
        expect.stringContaining('admin:users:limit:50:offset:0:tenant:tenant-id:search:search:includeRoles:true'),
        300,
        expect.any(String)
      );
      expect(result).toHaveProperty('data');
      expect(result).toHaveProperty('meta');
    });

    it('should use cached data when available', async () => {
      const cachedData = JSON.stringify({
        data: [],
        meta: { total: 0, limit: 50, offset: 0, hasNext: false },
      });
      jest.spyOn(redis, 'get').mockResolvedValue(cachedData);

      const result = await service.findAllUsers(50, 0);

      expect(redis.get).toHaveBeenCalledWith(
        'admin:users:limit:50:offset:0:tenant:all:search:none:includeRoles:false'
      );
      expect(result).toEqual(JSON.parse(cachedData));
      expect(prisma.user.findMany).not.toHaveBeenCalled();
    });

    it('should throw BadRequestException for invalid limit', async () => {
      await expect(service.findAllUsers(150, 0)).rejects.toThrow(BadRequestException);
    });

    it('should throw BadRequestException for invalid offset', async () => {
      await expect(service.findAllUsers(50, -1)).rejects.toThrow(BadRequestException);
    });

    it('should throw NotFoundException for non-existent tenant', async () => {
      jest.spyOn(redis, 'get').mockResolvedValue(null);
      jest.spyOn(prisma.tenant, 'findUnique').mockResolvedValue(null);

      await expect(service.findAllUsers(50, 0, 'non-existent-tenant')).rejects.toThrow(NotFoundException);
    });
  });

  describe('updateUserRole', () => {
    it('should assign roles successfully', async () => {
      const updateRoleDto: UpdateUserRoleDto = {
        userId: 'user-id',
        tenantId: 'tenant-id',
        operation: UserRoleOperation.ASSIGN,
        roles: [{ roleId: 'role-id' }],
      };

      const mockUser = {
        id: 'user-id',
        tenantId: 'tenant-id',
        roles: [],
        tenant: { id: 'tenant-id', name: 'Test Tenant', slug: 'test-tenant' },
      };

      const mockRole = {
        id: 'role-id',
        tenantId: 'tenant-id',
        name: 'Admin',
        description: 'Admin role',
        isSystem: false,
        isActive: true,
        createdAt: new Date(),
        validFrom: new Date(),
        validUntil: new Date(),
      };

      const mockUpdatedUser = {
        ...mockUser,
        roles: [{ roleId: 'role-id', role: mockRole }],
      };

      jest.spyOn(prisma.user, 'findUnique').mockResolvedValue(mockUser);
      jest.spyOn(prisma.role, 'findMany').mockResolvedValue([mockRole]);
      jest.spyOn(service as any, 'validateRoleHierarchy').mockResolvedValue();
      jest.spyOn(service as any, 'assignRoles').mockResolvedValue(mockUpdatedUser);
      jest.spyOn(service as any, 'invalidateUserCache').mockResolvedValue();

      const result = await service.updateUserRole(updateRoleDto, 'admin-id');

      expect(prisma.user.findUnique).toHaveBeenCalledWith({
        where: { id: 'user-id' },
        include: { tenant: true, roles: { include: { role: true } } },
      });
      expect(service['assignRoles']).toHaveBeenCalledWith('user-id', [{ roleId: 'role-id' }], 'admin-id', undefined);
      expect(eventLog.logEvent).toHaveBeenCalledWith('USER_PROFILE_UPDATE', expect.any(Object));
      expect(service['invalidateUserCache']).toHaveBeenCalledWith('user-id', 'tenant-id');
      expect(result.message).toBe('Roles assigned successfully');
    });

    it('should throw NotFoundException for non-existent user', async () => {
      jest.spyOn(prisma.user, 'findUnique').mockResolvedValue(null);

      const updateRoleDto: UpdateUserRoleDto = {
        userId: 'non-existent-user',
        tenantId: 'tenant-id',
        operation: UserRoleOperation.ASSIGN,
        roles: [{ roleId: 'role-id' }],
      };

      await expect(service.updateUserRole(updateRoleDto, 'admin-id')).rejects.toThrow(NotFoundException);
    });

    it('should throw ForbiddenException for tenant mismatch', async () => {
      const mockUser = {
        id: 'user-id',
        tenantId: 'different-tenant',
        roles: [],
        tenant: { id: 'different-tenant', name: 'Different Tenant', slug: 'different-tenant' },
      };

      jest.spyOn(prisma.user, 'findUnique').mockResolvedValue(mockUser);

      const updateRoleDto: UpdateUserRoleDto = {
        userId: 'user-id',
        tenantId: 'tenant-id',
        operation: UserRoleOperation.ASSIGN,
        roles: [{ roleId: 'role-id' }],
      };

      await expect(service.updateUserRole(updateRoleDto, 'admin-id')).rejects.toThrow(ForbiddenException);
    });

    it('should handle temporary role assignment', async () => {
      const updateRoleDto: UpdateUserRoleDto = {
        userId: 'user-id',
        tenantId: 'tenant-id',
        operation: UserRoleOperation.TEMPORARY_ASSIGN,
        roles: [{ roleId: 'role-id' }],
        temporaryDurationDays: 7,
      };

      const mockUser = {
        id: 'user-id',
        tenantId: 'tenant-id',
        roles: [],
        tenant: { id: 'tenant-id', name: 'Test Tenant', slug: 'test-tenant' },
      };

      const mockRole = {
        id: 'role-id',
        tenantId: 'tenant-id',
        name: 'Admin',
        description: 'Admin role',
        isSystem: false,
        isActive: true,
        createdAt: new Date(),
        validFrom: new Date(),
        validUntil: new Date(),
      };

      const mockUpdatedUser = {
        ...mockUser,
        roles: [{ roleId: 'role-id', role: mockRole }],
      };

      jest.spyOn(prisma.user, 'findUnique').mockResolvedValue(mockUser);
      jest.spyOn(prisma.role, 'findMany').mockResolvedValue([mockRole]);
      jest.spyOn(service as any, 'validateRoleHierarchy').mockResolvedValue();
      jest.spyOn(service as any, 'temporaryAssignRoles').mockResolvedValue(mockUpdatedUser);
      jest.spyOn(service as any, 'invalidateUserCache').mockResolvedValue();

      const result = await service.updateUserRole(updateRoleDto, 'admin-id');

      expect(service['temporaryAssignRoles']).toHaveBeenCalledWith(
        'user-id',
        [{ roleId: 'role-id' }],
        7,
        'admin-id',
        undefined
      );
    });
  });

  describe('getAuditEvents', () => {
    it('should return paginated audit events', async () => {
      const mockEvents = {
        data: [],
        meta: { total: 0, limit: 50, offset: 0, hasNext: false },
      };

      jest.spyOn(eventLog, 'queryEvents').mockResolvedValue(mockEvents);

      const result = await service.getAuditEvents(50, 0, 'USER_PROFILE_UPDATE', 'user-id', new Date(), new Date(), 'SECURITY', 'tenant-id');

      expect(eventLog.queryEvents).toHaveBeenCalledWith({
        type: 'USER_PROFILE_UPDATE',
        userId: 'user-id',
        startDate: expect.any(Date),
        endDate: expect.any(Date),
        severity: 'SECURITY',
        tenantId: 'tenant-id',
        limit: 50,
        offset: 0,
      });
      expect(result).toEqual(mockEvents);
    });

    it('should throw BadRequestException for invalid limit', async () => {
      await expect(service.getAuditEvents(150, 0)).rejects.toThrow(BadRequestException);
    });
  });

  describe('getRoleAnalytics', () => {
    it('should return role analytics for a tenant', async () => {
      const mockTenant = { id: 'tenant-id' };
      const mockRoleStats = [{ name: 'Admin', _count: 1, _avg: { priority: 1 } }];
      const mockUserRoleStats = { _count: { id: 1, userId: 1, roleId: 1 } };
      const mockPermissionStats = { _count: { id: 1 } };

      jest.spyOn(prisma.tenant, 'findUnique').mockResolvedValue(mockTenant);
      jest.spyOn(prisma.role, 'groupBy').mockResolvedValue(mockRoleStats);
      jest.spyOn(prisma.userRole, 'aggregate').mockResolvedValue(mockUserRoleStats);
      jest.spyOn(prisma.rolePermission, 'aggregate').mockResolvedValue(mockPermissionStats);

      const result = await service.getRoleAnalytics('tenant-id');

      expect(prisma.tenant.findUnique).toHaveBeenCalledWith({
        where: { id: 'tenant-id' },
        select: { id: true },
      });
      expect(prisma.role.groupBy).toHaveBeenCalledWith({
        by: ['name'],
        where: { tenantId: 'tenant-id' },
        _count: true,
        _avg: { priority: true },
      });
      expect(result).toHaveProperty('roleDistribution');
      expect(result).toHaveProperty('userRoleStats');
      expect(result).toHaveProperty('permissionStats');
      expect(result).toHaveProperty('timestamp');
    });

    it('should throw NotFoundException for non-existent tenant', async () => {
      jest.spyOn(prisma.tenant, 'findUnique').mockResolvedValue(null);

      await expect(service.getRoleAnalytics('non-existent-tenant')).rejects.toThrow(NotFoundException);
    });
  });

  describe('getTenantUserStats', () => {
    it('should return user statistics for a tenant', async () => {
      const mockTenant = { id: 'tenant-id' };
      const mockUserCount = 10;
      const mockActiveUserCount = 8;
      const mockRoleDistribution = [{ name: 'Admin', _count: 2 }];
      const mockSecurityStats = 5;

      jest.spyOn(prisma.tenant, 'findUnique').mockResolvedValue(mockTenant);
      jest.spyOn(prisma.user, 'count').mockResolvedValueOnce(mockUserCount).mockResolvedValueOnce(mockActiveUserCount);
      jest.spyOn(prisma.role, 'groupBy').mockResolvedValue(mockRoleDistribution);
      jest.spyOn(prisma.event, 'count').mockResolvedValue(mockSecurityStats);

      const result = await service.getTenantUserStats('tenant-id');

      expect(prisma.tenant.findUnique).toHaveBeenCalledWith({
        where: { id: 'tenant-id' },
        select: { id: true },
      });
      expect(result).toHaveProperty('totalUsers');
      expect(result).toHaveProperty('activeUsers');
      expect(result).toHaveProperty('roleDistribution');
      expect(result).toHaveProperty('securityEventsLast30Days');
      expect(result).toHaveProperty('timestamp');
    });

    it('should throw NotFoundException for non-existent tenant', async () => {
      jest.spyOn(prisma.tenant, 'findUnique').mockResolvedValue(null);

      await expect(service.getTenantUserStats('non-existent-tenant')).rejects.toThrow(NotFoundException);
    });
  });

  describe('bulkUpdateUserRoles', () => {
    it('should perform bulk role updates successfully', async () => {
      const userIds = ['user1', 'user2'];
      const roleIds = ['role1', 'role2'];
      const mockUsers = [
        { id: 'user1', tenantId: 'tenant-id' },
        { id: 'user2', tenantId: 'tenant-id' },
      ];
      const mockRoles = [
        { id: 'role1', tenantId: 'tenant-id' },
        { id: 'role2', tenantId: 'tenant-id' },
      ];
      const mockUpdateResult = { message: 'Roles assigned successfully' };

      jest.spyOn(prisma.user, 'findMany').mockResolvedValue(mockUsers);
      jest.spyOn(prisma.role, 'findMany').mockResolvedValue(mockRoles);
      jest.spyOn(service, 'updateUserRole').mockResolvedValue(mockUpdateResult);

      const result = await service.bulkUpdateUserRoles(userIds, roleIds, 'ASSIGN', 'admin-id', 'reason');

      expect(prisma.user.findMany).toHaveBeenCalledWith({
        where: { id: { in: userIds } },
        select: { id: true, tenantId: true },
      });
      expect(service.updateUserRole).toHaveBeenCalledTimes(2);
      expect(result).toHaveProperty('totalUsers', 2);
      expect(result).toHaveProperty('successfulUpdates', 2);
      expect(result).toHaveProperty('failedUpdates', 0);
      expect(result).toHaveProperty('results');
    });

    it('should throw BadRequestException for too many users', async () => {
      const userIds = Array(101).fill('user-id').map((_, i) => `user${i}`);
      const roleIds = ['role-id'];

      await expect(service.bulkUpdateUserRoles(userIds, roleIds, 'ASSIGN', 'admin-id', 'reason')).rejects.toThrow(BadRequestException);
    });

    it('should throw NotFoundException for non-existent users', async () => {
      const userIds = ['user1', 'user2'];
      const roleIds = ['role1'];
      const mockUsers = [{ id: 'user1', tenantId: 'tenant-id' }]; // Missing user2

      jest.spyOn(prisma.user, 'findMany').mockResolvedValue(mockUsers);

      await expect(service.bulkUpdateUserRoles(userIds, roleIds, 'ASSIGN', 'admin-id', 'reason')).rejects.toThrow(NotFoundException);
    });
  });

  describe('getUserRoleDetails', () => {
    it('should return user role details from cache', async () => {
      const mockCachedData = JSON.stringify({
        userId: 'user-id',
        name: 'Test User',
        email: 'test@example.com',
        roles: [],
      });

      jest.spyOn(redis, 'get').mockResolvedValue(mockCachedData);

      const result = await service.getUserRoleDetails('user-id');

      expect(redis.get).toHaveBeenCalledWith('user:user-id:roles');
      expect(result).toEqual(JSON.parse(mockCachedData));
      expect(prisma.user.findUnique).not.toHaveBeenCalled();
    });

    it('should return user role details from database', async () => {
      const mockUserWithRoles = {
        id: 'user-id',
        name: 'Test User',
        email: 'test@example.com',
        roles: [
          {
            role: {
              id: 'role-id',
              name: 'Admin',
              description: 'Admin role',
              permissions: [
                {
                  permission: {
                    id: 'perm-id',
                    name: 'Manage Users',
                    resource: 'users',
                    action: 'UPDATE',
                  },
                  allowed: true,
                },
              ],
            },
          },
        ],
      };

      jest.spyOn(redis, 'get').mockResolvedValue(null);
      jest.spyOn(prisma.user, 'findUnique').mockResolvedValue(mockUserWithRoles);

      const result = await service.getUserRoleDetails('user-id');

      expect(redis.get).toHaveBeenCalledWith('user:user-id:roles');
      expect(prisma.user.findUnique).toHaveBeenCalledWith({
        where: { id: 'user-id' },
        include: {
          roles: {
            include: {
              role: {
                include: {
                  permissions: {
                    include: {
                      permission: true,
                    },
                  },
                },
              },
            },
          },
        },
      });
      expect(redis.setex).toHaveBeenCalledWith('user:user-id:roles', 900, expect.any(String));
      expect(result).toHaveProperty('userId', 'user-id');
      expect(result).toHaveProperty('name', 'Test User');
      expect(result).toHaveProperty('email', 'test@example.com');
      expect(result).toHaveProperty('roles');
    });

    it('should throw NotFoundException for non-existent user', async () => {
      jest.spyOn(redis, 'get').mockResolvedValue(null);
      jest.spyOn(prisma.user, 'findUnique').mockResolvedValue(null);

      await expect(service.getUserRoleDetails('non-existent-user')).rejects.toThrow(NotFoundException);
    });
  });
});