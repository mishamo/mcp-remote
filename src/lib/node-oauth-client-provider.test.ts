import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest'
import { NodeOAuthClientProvider } from './node-oauth-client-provider'
import type { OAuthProviderOptions } from './types'
import * as mcpAuthConfig from './mcp-auth-config'
import * as utils from './utils'

// Mock the modules
vi.mock('./mcp-auth-config')
vi.mock('./utils')
vi.mock('open')
vi.mock('strict-url-sanitise')

const mockWriteJsonFile = vi.mocked(mcpAuthConfig.writeJsonFile)
const mockReadJsonFile = vi.mocked(mcpAuthConfig.readJsonFile)
const mockDeleteConfigFile = vi.mocked(mcpAuthConfig.deleteConfigFile)
const mockGetServerUrlHash = vi.mocked(utils.getServerUrlHash)

describe('NodeOAuthClientProvider Scope Handling', () => {
  let provider: NodeOAuthClientProvider
  const options: OAuthProviderOptions = {
    serverUrl: 'https://example.com',
    callbackPort: 3000,
    host: 'localhost',
  }

  beforeEach(() => {
    vi.clearAllMocks()
    // Mock getServerUrlHash to return a consistent value
    mockGetServerUrlHash.mockReturnValue('test-server-hash')
    provider = new NodeOAuthClientProvider(options)
  })

  afterEach(() => {
    vi.resetAllMocks()
  })

  describe('clientMetadata', () => {
    it('should include default scope in client metadata', () => {
      const metadata = provider.clientMetadata
      expect(metadata.scope).toBe('openid email profile')
    })

    it('should include custom scope from options in client metadata', () => {
      const providerWithCustomScope = new NodeOAuthClientProvider({
        ...options,
        scopes: 'custom scope read write',
      })

      const metadata = providerWithCustomScope.clientMetadata
      expect(metadata.scope).toBe('custom scope read write')
    })

    it('should include scope in client metadata with static OAuth metadata', () => {
      const providerWithStaticMetadata = new NodeOAuthClientProvider({
        ...options,
        staticOAuthClientMetadata: {
          redirect_uris: ['http://localhost:3000/oauth/callback'],
          client_name: 'Custom Client',
        },
      })

      const metadata = providerWithStaticMetadata.clientMetadata
      expect(metadata.scope).toBe('openid email profile')
      expect(metadata.client_name).toBe('Custom Client')
    })
  })

  describe('scope extraction helper method', () => {
    it('should extract scope from various registration response formats', () => {
      // Test the private method through type assertion
      const extractMethod = (provider as any).extractScopesFromRegistration.bind(provider)

      // Test scope field
      expect(extractMethod({ scope: 'custom scope' })).toBe('custom scope')

      // Test default_scope field
      expect(extractMethod({ default_scope: 'default scope' })).toBe('default scope')

      // Test scopes array
      expect(extractMethod({ scopes: ['read', 'write', 'admin'] })).toBe('read write admin')

      // Test default_scopes array
      expect(extractMethod({ default_scopes: ['openid', 'profile'] })).toBe('openid profile')

      // Test fallback when no scope fields present
      expect(extractMethod({})).toBe('openid email profile')

      // Test priority order - scope takes precedence
      expect(
        extractMethod({
          scope: 'priority scope',
          default_scope: 'secondary scope',
          scopes: ['array', 'scope'],
        }),
      ).toBe('priority scope')
    })
  })

  describe('scope extraction from registration response', () => {
    it('should extract scope from registration response', async () => {
      const registrationResponse = {
        client_id: 'test-client-id',
        scope: 'openid email profile custom',
      }

      await provider.saveClientInformation(registrationResponse as any)

      expect(mockWriteJsonFile).toHaveBeenCalledWith('test-server-hash', 'client_info.json', registrationResponse)
      expect(mockWriteJsonFile).toHaveBeenCalledWith('test-server-hash', 'scopes.json', { scopes: 'openid email profile custom' })
    })

    it('should extract default_scope from registration response', async () => {
      const registrationResponse = {
        client_id: 'test-client-id',
        default_scope: 'openid email',
      }

      await provider.saveClientInformation(registrationResponse as any)

      expect(mockWriteJsonFile).toHaveBeenCalledWith('test-server-hash', 'scopes.json', { scopes: 'openid email' })
    })

    it('should handle array scopes from registration response', async () => {
      const registrationResponse = {
        client_id: 'test-client-id',
        scopes: ['openid', 'email', 'profile'],
      }

      await provider.saveClientInformation(registrationResponse as any)

      expect(mockWriteJsonFile).toHaveBeenCalledWith('test-server-hash', 'scopes.json', { scopes: 'openid email profile' })
    })

    it('should handle array default_scopes from registration response', async () => {
      const registrationResponse = {
        client_id: 'test-client-id',
        default_scopes: ['openid', 'email'],
      }

      await provider.saveClientInformation(registrationResponse as any)

      expect(mockWriteJsonFile).toHaveBeenCalledWith('test-server-hash', 'scopes.json', { scopes: 'openid email' })
    })

    it('should use fallback scope when none provided in registration response', async () => {
      const registrationResponse = {
        client_id: 'test-client-id',
      }

      await provider.saveClientInformation(registrationResponse as any)

      expect(mockWriteJsonFile).toHaveBeenCalledWith('test-server-hash', 'scopes.json', { scopes: 'openid email profile' })
    })
  })

  describe('scope inclusion in authorization URL', () => {
    it('should include default scope in authorization URL', async () => {
      const authUrl = new URL('https://auth.example.com/oauth/authorize')
      await provider.redirectToAuthorization(authUrl)

      expect(authUrl.searchParams.get('scope')).toBe('openid email profile')
    })

    it('should include custom scope from options in authorization URL', async () => {
      const providerWithCustomScope = new NodeOAuthClientProvider({
        ...options,
        scopes: 'custom scope read write',
      })

      const authUrl = new URL('https://auth.example.com/oauth/authorize')
      await providerWithCustomScope.redirectToAuthorization(authUrl)

      expect(authUrl.searchParams.get('scope')).toBe('custom scope read write')
    })

    it('should include updated scopes after registration in authorization URL', async () => {
      // Start with default scopes
      const provider = new NodeOAuthClientProvider(options)

      // Simulate scopes being updated from registration response
      ;(provider as any)._scopes = 'openid email profile custom'

      const authUrl = new URL('https://auth.example.com/oauth/authorize')
      await provider.redirectToAuthorization(authUrl)

      expect(authUrl.searchParams.get('scope')).toBe('openid email profile custom')
    })

    it('should include resource parameter alongside scope', async () => {
      const providerWithResource = new NodeOAuthClientProvider({
        ...options,
        authorizeResource: 'test-resource',
        scopes: 'openid email',
      })

      const authUrl = new URL('https://auth.example.com/oauth/authorize')
      await providerWithResource.redirectToAuthorization(authUrl)

      expect(authUrl.searchParams.get('scope')).toBe('openid email')
      expect(authUrl.searchParams.get('resource')).toBe('test-resource')
    })
  })

  describe('scope loading from storage', () => {
    it('should load stored scopes when getting client information', async () => {
      const clientInfo = { client_id: 'test-client-id' }
      const scopesData = { scopes: 'openid email profile custom' }

      mockReadJsonFile
        .mockResolvedValueOnce(clientInfo) // client_info.json
        .mockResolvedValueOnce(scopesData) // scopes.json

      const result = await provider.clientInformation()

      expect(result).toEqual(clientInfo)
      expect(mockReadJsonFile).toHaveBeenCalledWith('test-server-hash', 'client_info.json', expect.any(Object))
      expect(mockReadJsonFile).toHaveBeenCalledWith('test-server-hash', 'scopes.json', expect.any(Object))

      // Verify scopes were loaded into the provider
      expect((provider as any)._scopes).toBe('openid email profile custom')
    })

    it('should handle missing scopes file gracefully', async () => {
      const clientInfo = { client_id: 'test-client-id' }

      mockReadJsonFile
        .mockResolvedValueOnce(clientInfo) // client_info.json
        .mockResolvedValueOnce(undefined) // scopes.json (not found)

      const result = await provider.clientInformation()

      expect(result).toEqual(clientInfo)
    })
  })

  describe('credential invalidation', () => {
    it('should delete scopes when invalidating all credentials', async () => {
      await provider.invalidateCredentials('all')

      expect(mockDeleteConfigFile).toHaveBeenCalledWith('test-server-hash', 'scopes.json')
    })

    it('should delete scopes when invalidating client credentials', async () => {
      await provider.invalidateCredentials('client')

      expect(mockDeleteConfigFile).toHaveBeenCalledWith('test-server-hash', 'client_info.json')
      expect(mockDeleteConfigFile).toHaveBeenCalledWith('test-server-hash', 'scopes.json')
    })

    it('should not delete scopes when invalidating only tokens', async () => {
      await provider.invalidateCredentials('tokens')

      expect(mockDeleteConfigFile).toHaveBeenCalledWith('test-server-hash', 'tokens.json')
      expect(mockDeleteConfigFile).not.toHaveBeenCalledWith('test-server-hash', 'scopes.json')
    })
  })
})
