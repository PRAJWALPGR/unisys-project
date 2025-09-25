package com.example.detection.service

import android.content.Context
import android.content.SharedPreferences
import android.util.Base64
import android.util.Log
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKeys
import com.google.gson.Gson
import java.io.File
import java.io.FileOutputStream
import java.io.BufferedWriter
import java.io.FileWriter
import java.security.SecureRandom
import java.util.Calendar
import java.util.Random
import java.util.UUID
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec
import kotlin.random.Random as KotlinRandom

/**
 * Deception Layer Service
 * Creates convincing decoys, fake API tokens, and planted sensitive data to attract attackers.
 */
class DeceptionLayerService(private val context: Context) {

    private val TAG = "DeceptionLayerService"
    
    // Gson for JSON serialization
    private val gson = Gson()
    
    // Random generator for secure token creation
    private val secureRandom = SecureRandom()
    
    // Cached fake credentials
    private var cachedApiKey: String? = null
    private var cachedJwtToken: String? = null
    
    // Fake credentials for the deception layer
    private val fakeCredentials = mutableMapOf<String, String>()
    
    // Master key alias for encryption
    private val masterKeyAlias by lazy {
        MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC)
    }
    
    // Shared preferences for storing decoy settings
    private val decoyPrefs by lazy {
        EncryptedSharedPreferences.create(
            "decoy_settings",
            masterKeyAlias,
            context,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    }
    
    init {
        // Initialize basic fake credentials
        fakeCredentials["api_key"] = generateApiKey()
        fakeCredentials["auth_token"] = generateAuthToken()
        fakeCredentials["refresh_token"] = generateRefreshToken()
        fakeCredentials["client_id"] = "c" + UUID.randomUUID().toString().replace("-", "").substring(0, 20)
        fakeCredentials["client_secret"] = UUID.randomUUID().toString().replace("-", "") + UUID.randomUUID().toString().substring(0, 8)
        
        // Setup decoy files and settings
        setupDeceptionLayer()
    }
    
    /**
     * Setup all deception components
     */
    private fun setupDeceptionLayer() {
        try {
            // 1. Create decoy shared preferences data
            setupDecoySharedPreferences()
            
            // 2. Create fake sensitive files
            setupDecoyFiles()
            
            // 3. Setup dummy network endpoints
            setupDummyEndpoints()
        } catch (e: Exception) {
            Log.e(TAG, "Error setting up deception layer: ${e.message}")
            e.printStackTrace()
        }
    }
    
    /**
     * Setup fake SharedPreferences settings that would be attractive to attackers
     */
    private fun setupDecoySharedPreferences() {
        val editor = decoyPrefs.edit()
        
        // Fake premium subscription status
        editor.putBoolean("isPremiumUser", true)
        editor.putLong("premiumExpiryDate", System.currentTimeMillis() + 30 * 24 * 60 * 60 * 1000L) // 30 days in future
        
        // Fake user details
        editor.putString("username", "test_admin")
        editor.putString("email", "admin@" + getRandomDomain())
        editor.putString("accountType", "ADMIN")
        
        // Fake API tokens
        editor.putString("apiKey", fakeCredentials["api_key"])
        editor.putString("authToken", fakeCredentials["auth_token"])
        editor.putString("refreshToken", fakeCredentials["refresh_token"])
        
        // Fake feature flags
        editor.putBoolean("developerMode", true)
        editor.putBoolean("debugEnabled", true)
        editor.putBoolean("bypassSecurity", true)
        editor.putBoolean("allFeaturesUnlocked", true)
        
        // Apply changes
        editor.apply()
    }
    
    /**
     * Create fake credential and configuration files
     */
    private fun setupDecoyFiles() {
        try {
            // Create base directories
            val decoyDir = File(context.filesDir, "config")
            if (!decoyDir.exists()) {
                decoyDir.mkdirs()
            }
            
            val secureDir = File(context.filesDir, "secure")
            if (!secureDir.exists()) {
                secureDir.mkdirs()
            }
            
            // 1. Create fake config.json
            val configJson = mapOf(
                "env" to "production",
                "debug" to true,
                "apiEndpoint" to "https://api." + getRandomDomain() + "/v2",
                "apiKey" to fakeCredentials["api_key"],
                "clientId" to fakeCredentials["client_id"],
                "clientSecret" to fakeCredentials["client_secret"],
                "maxRetries" to 5,
                "timeout" to 30000,
                "encryptionEnabled" to true,
                "features" to mapOf(
                    "premium" to true,
                    "analytics" to true,
                    "backup" to true,
                    "sync" to true
                )
            )
            val configFile = File(decoyDir, "config.json")
            FileOutputStream(configFile).use { output ->
                output.write(gson.toJson(configJson).toByteArray())
            }
            
            // 2. Create fake credentials.json
            val userCredentials = mapOf(
                "username" to "test_admin",
                "password" to "ENCRYPTED:" + Base64.encodeToString(generateRandomBytes(32), Base64.DEFAULT),
                "email" to "admin@" + getRandomDomain(),
                "token" to fakeCredentials["auth_token"],
                "refreshToken" to fakeCredentials["refresh_token"],
                "isAdmin" to true,
                "permissions" to listOf("READ", "WRITE", "EXECUTE", "DELETE", "ADMIN"),
                "lastLogin" to System.currentTimeMillis()
            )
            val credentialsFile = File(secureDir, "credentials.json")
            FileOutputStream(credentialsFile).use { output ->
                output.write(gson.toJson(userCredentials).toByteArray())
            }
            
            // 3. Create fake .env file
            val envFile = File(context.filesDir, ".env")
            BufferedWriter(FileWriter(envFile)).use { writer ->
                writer.write("API_KEY=${fakeCredentials["api_key"]}\n")
                writer.write("AUTH_TOKEN=${fakeCredentials["auth_token"]}\n")
                writer.write("REFRESH_TOKEN=${fakeCredentials["refresh_token"]}\n")
                writer.write("CLIENT_ID=${fakeCredentials["client_id"]}\n")
                writer.write("CLIENT_SECRET=${fakeCredentials["client_secret"]}\n")
                writer.write("DATABASE_URL=postgres://admin:${generateRandomPassword()}@db.${getRandomDomain()}:5432/app_prod\n")
                writer.write("REDIS_URL=redis://cache.${getRandomDomain()}:6379/0\n")
                writer.write("ENV=production\n")
                writer.write("DEBUG=true\n")
            }
            
            // 4. Create fake keystore file
            val keystoreFile = File(secureDir, "app.keystore")
            FileOutputStream(keystoreFile).use { output ->
                // Just write random bytes to simulate a keystore file
                output.write(generateRandomBytes(2048))
            }
            
            // 5. Create fake Firebase config
            val firebaseConfigJson = mapOf(
                "apiKey" to "AIza" + Base64.encodeToString(generateRandomBytes(8), Base64.DEFAULT).substring(0, 20),
                "authDomain" to "app-${randomString(6)}.firebaseapp.com",
                "projectId" to "app-${randomString(6)}",
                "storageBucket" to "app-${randomString(6)}.appspot.com",
                "messagingSenderId" to "${100000000 + KotlinRandom.nextInt(900000000)}",
                "appId" to "1:${100000000 + KotlinRandom.nextInt(900000000)}:web:${randomAlphaNumeric(8)}",
                "measurementId" to "G-${randomAlphaNumeric(10)}"
            )
            val firebaseConfigFile = File(decoyDir, "firebase-config.json")
            FileOutputStream(firebaseConfigFile).use { output ->
                output.write(gson.toJson(firebaseConfigJson).toByteArray())
            }
            
        } catch (e: Exception) {
            Log.e(TAG, "Error creating decoy files: ${e.message}")
            e.printStackTrace()
        }
    }
    
    /**
     * Setup dummy network endpoint configuration
     */
    private fun setupDummyEndpoints() {
        // Create file listing dummy API endpoints
        try {
            val apiDir = File(context.filesDir, "api")
            if (!apiDir.exists()) {
                apiDir.mkdirs()
            }
            
            val endpointsJson = mapOf(
                "base_url" to "https://api.${getRandomDomain()}/v2",
                "endpoints" to listOf(
                    mapOf(
                        "path" to "/auth/login",
                        "method" to "POST",
                        "requires_auth" to false,
                        "rate_limit" to 10
                    ),
                    mapOf(
                        "path" to "/auth/refresh",
                        "method" to "POST",
                        "requires_auth" to true,
                        "rate_limit" to 30
                    ),
                    mapOf(
                        "path" to "/users/me",
                        "method" to "GET",
                        "requires_auth" to true,
                        "rate_limit" to 50
                    ),
                    mapOf(
                        "path" to "/admin/users",
                        "method" to "GET",
                        "requires_auth" to true,
                        "requires_admin" to true,
                        "rate_limit" to 20
                    ),
                    mapOf(
                        "path" to "/payments/subscription",
                        "method" to "GET",
                        "requires_auth" to true,
                        "rate_limit" to 30
                    )
                ),
                "auth_header" to "Bearer ${fakeCredentials["auth_token"]}",
                "api_key_header" to "X-API-Key: ${fakeCredentials["api_key"]}"
            )
            
            val endpointsFile = File(apiDir, "endpoints.json")
            FileOutputStream(endpointsFile).use { output ->
                output.write(gson.toJson(endpointsJson).toByteArray())
            }
            
        } catch (e: Exception) {
            Log.e(TAG, "Error setting up dummy endpoints: ${e.message}")
            e.printStackTrace()
        }
    }
    
    /**
     * Get fake API key in AWS format
     */
    fun getApiKey(): String {
        if (cachedApiKey == null) {
            cachedApiKey = generateApiKey()
        }
        return cachedApiKey!!
    }
    
    /**
     * Get fake JWT token
     */
    fun getJwtToken(): String {
        if (cachedJwtToken == null) {
            cachedJwtToken = generateJwtToken()
        }
        return cachedJwtToken!!
    }
    
    /**
     * Get all fake credentials
     */
    fun getAllCredentials(): Map<String, String> {
        return fakeCredentials.toMap()
    }
    
    /**
     * Create AWS-style API key (20 characters)
     */
    private fun generateApiKey(): String {
        return "AKIA" + randomAlphaNumeric(16)
    }
    
    /**
     * Create convincing auth token
     */
    private fun generateAuthToken(): String {
        return randomAlphaNumeric(32)
    }
    
    /**
     * Create convincing refresh token
     */
    private fun generateRefreshToken(): String {
        return randomAlphaNumeric(40)
    }
    
    /**
     * Generate a convincing JWT token
     */
    private fun generateJwtToken(): String {
        // JWT structure: header.payload.signature
        val header = Base64.encodeToString(
            gson.toJson(mapOf(
                "alg" to "HS256",
                "typ" to "JWT"
            )).toByteArray(),
            Base64.URL_SAFE or Base64.NO_WRAP
        )
        
        // Create realistic payload with typical JWT claims
        val now = System.currentTimeMillis() / 1000
        val payload = Base64.encodeToString(
            gson.toJson(mapOf(
                "sub" to "user-${randomNumeric(6)}",
                "name" to "Test Admin",
                "admin" to true,
                "iat" to now,
                "exp" to now + 3600,
                "iss" to "https://auth.${getRandomDomain()}/",
                "aud" to listOf("https://api.${getRandomDomain()}/"),
                "permissions" to listOf("read:all", "write:all", "admin:all")
            )).toByteArray(),
            Base64.URL_SAFE or Base64.NO_WRAP
        )
        
        // Create a fake signature (in a real JWT this would be cryptographically signed)
        val signature = Base64.encodeToString(generateRandomBytes(32), Base64.URL_SAFE or Base64.NO_WRAP)
        
        return "$header.$payload.$signature"
    }
    
    /**
     * Generate random bytes
     */
    private fun generateRandomBytes(length: Int): ByteArray {
        val bytes = ByteArray(length)
        secureRandom.nextBytes(bytes)
        return bytes
    }
    
    /**
     * Generate random alphanumeric string
     */
    private fun randomAlphaNumeric(length: Int): String {
        val chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        return (1..length)
            .map { chars[KotlinRandom.nextInt(chars.length)] }
            .joinToString("")
    }
    
    /**
     * Generate random alphabetic string
     */
    private fun randomString(length: Int): String {
        val chars = "abcdefghijklmnopqrstuvwxyz"
        return (1..length)
            .map { chars[KotlinRandom.nextInt(chars.length)] }
            .joinToString("")
    }
    
    /**
     * Generate random numeric string
     */
    private fun randomNumeric(length: Int): String {
        val chars = "0123456789"
        return (1..length)
            .map { chars[KotlinRandom.nextInt(chars.length)] }
            .joinToString("")
    }
    
    /**
     * Generate random domain name
     */
    private fun getRandomDomain(): String {
        val domains = listOf(
            "example.com", "testapp.io", "secureapp.dev", "appdata.cloud",
            "apiservices.net", "devplatform.com", "securecloud.io", "datastore.app"
        )
        return domains.random()
    }
    
    /**
     * Generate random complex password
     */
    private fun generateRandomPassword(): String {
        val upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        val lower = "abcdefghijklmnopqrstuvwxyz"
        val digits = "0123456789"
        val special = "!@#$%^&*()-_=+[]{}|;:,.<>?"
        
        val allChars = upper + lower + digits + special
        val password = StringBuilder()
        
        // Ensure at least one character from each category
        password.append(upper[KotlinRandom.nextInt(upper.length)])
        password.append(lower[KotlinRandom.nextInt(lower.length)])
        password.append(digits[KotlinRandom.nextInt(digits.length)])
        password.append(special[KotlinRandom.nextInt(special.length)])
        
        // Fill remaining length with random characters
        for (i in 0 until 8) {
            password.append(allChars[KotlinRandom.nextInt(allChars.length)])
        }
        
        // Shuffle the password
        return password.toString().toCharArray().apply { shuffle() }.joinToString("")
    }
    
    /**
     * Refresh credentials periodically to maintain deception
     */
    fun refreshCredentials() {
        cachedApiKey = generateApiKey()
        cachedJwtToken = generateJwtToken()
        
        fakeCredentials["api_key"] = cachedApiKey!!
        fakeCredentials["auth_token"] = generateAuthToken()
        fakeCredentials["refresh_token"] = generateRefreshToken()
        
        // Update SharedPreferences
        decoyPrefs.edit().apply {
            putString("apiKey", fakeCredentials["api_key"])
            putString("authToken", fakeCredentials["auth_token"])
            putString("refreshToken", fakeCredentials["refresh_token"])
            apply()
        }
    }
} 