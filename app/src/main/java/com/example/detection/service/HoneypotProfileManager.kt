package com.example.detection.service

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKeys
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import java.util.concurrent.atomic.AtomicReference

/**
 * Honeypot Profile Manager
 * Manages trap sensitivity profiles and settings to customize honeypot behavior.
 */
class HoneypotProfileManager(
    private val context: Context,
    private val cloneDetectionService: CloneDetectionService,
    private val trapGenerator: DynamicTrapGenerator? = null,
    private val aiEngine: HoneypotAIEngine? = null
) {
    // Available profile types
    enum class ProfileType {
        PASSIVE,     // Low sensitivity, minimal traps
        BALANCED,    // Medium sensitivity, standard traps
        PARANOID     // High sensitivity, maximum traps
    }
    
    // Frequency options for scan and analysis
    enum class ScanFrequency {
        LOW,    // Less frequent scanning
        MEDIUM, // Standard scanning frequency
        HIGH    // Aggressive, frequent scanning
    }
    
    // Current active profile
    private val currentProfile = AtomicReference<Profile>(Profile())
    
    // Track profile changes
    private var profileChangeTimestamp = System.currentTimeMillis()
    
    // Master key alias for encryption
    private val masterKeyAlias by lazy {
        MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC)
    }
    
    // Secure preferences for storing profile settings
    private val profilePrefs by lazy {
        EncryptedSharedPreferences.create(
            "honeypot_profile_prefs",
            masterKeyAlias,
            context,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    }
    
    init {
        // Load saved profile or use default
        loadSavedProfile()
    }
    
    /**
     * Get the current active profile
     */
    fun getCurrentProfile(): Profile {
        return currentProfile.get()
    }
    
    /**
     * Set a new profile type (with default settings for that type)
     */
    fun setProfileType(type: ProfileType) {
        val newProfile = when (type) {
            ProfileType.PASSIVE -> createPassiveProfile()
            ProfileType.BALANCED -> createBalancedProfile()
            ProfileType.PARANOID -> createParanoidProfile()
        }
        
        setProfile(newProfile)
    }
    
    /**
     * Set a custom profile
     */
    fun setProfile(profile: Profile) {
        // Store the new profile
        currentProfile.set(profile)
        profileChangeTimestamp = System.currentTimeMillis()
        
        // Apply profile settings
        applyProfile(profile)
        
        // Save to preferences
        saveProfile(profile)
    }
    
    /**
     * Update a single setting in the current profile
     */
    fun updateSetting(key: String, value: Any) {
        val profile = currentProfile.get().copy()
        
        when (key) {
            "trapTriggerThreshold" -> profile.trapTriggerThreshold = value as Int
            "maxTrapsCount" -> profile.maxTrapsCount = value as Int
            "trapDynamicGeneration" -> profile.trapDynamicGeneration = value as Boolean
            "anomalyDetectionEnabled" -> profile.anomalyDetectionEnabled = value as Boolean
            "autoBlockEnabled" -> profile.autoBlockEnabled = value as Boolean
            "scanFrequency" -> profile.scanFrequency = value as ScanFrequency
            "alertsEnabled" -> profile.alertsEnabled = value as Boolean
            "decoyFilesEnabled" -> profile.decoyFilesEnabled = value as Boolean
            "cloudSyncEnabled" -> profile.cloudSyncEnabled = value as Boolean
            "threatIntelligenceEnabled" -> profile.threatIntelligenceEnabled = value as Boolean
            "anomalyThreshold" -> profile.anomalyThreshold = value as Double
        }
        
        setProfile(profile)
    }
    
    /**
     * Load the saved profile from preferences
     */
    private fun loadSavedProfile() {
        val profileType = ProfileType.valueOf(
            profilePrefs.getString("profileType", ProfileType.BALANCED.name) ?: ProfileType.BALANCED.name
        )
        
        val profile = when (profileType) {
            ProfileType.PASSIVE -> createPassiveProfile()
            ProfileType.BALANCED -> createBalancedProfile()
            ProfileType.PARANOID -> createParanoidProfile()
        }
        
        // Load custom settings that may override the defaults
        profile.trapTriggerThreshold = profilePrefs.getInt("trapTriggerThreshold", profile.trapTriggerThreshold)
        profile.maxTrapsCount = profilePrefs.getInt("maxTrapsCount", profile.maxTrapsCount)
        profile.trapDynamicGeneration = profilePrefs.getBoolean("trapDynamicGeneration", profile.trapDynamicGeneration)
        profile.anomalyDetectionEnabled = profilePrefs.getBoolean("anomalyDetectionEnabled", profile.anomalyDetectionEnabled)
        profile.autoBlockEnabled = profilePrefs.getBoolean("autoBlockEnabled", profile.autoBlockEnabled)
        profile.scanFrequency = ScanFrequency.valueOf(
            profilePrefs.getString("scanFrequency", profile.scanFrequency.name) ?: profile.scanFrequency.name
        )
        profile.alertsEnabled = profilePrefs.getBoolean("alertsEnabled", profile.alertsEnabled)
        profile.decoyFilesEnabled = profilePrefs.getBoolean("decoyFilesEnabled", profile.decoyFilesEnabled)
        profile.cloudSyncEnabled = profilePrefs.getBoolean("cloudSyncEnabled", profile.cloudSyncEnabled)
        profile.threatIntelligenceEnabled = profilePrefs.getBoolean("threatIntelligenceEnabled", profile.threatIntelligenceEnabled)
        profile.anomalyThreshold = profilePrefs.getFloat("anomalyThreshold", profile.anomalyThreshold.toFloat()).toDouble()
        
        // Set the loaded profile
        currentProfile.set(profile)
        
        // Apply it to the system
        applyProfile(profile)
    }
    
    /**
     * Save the current profile to preferences
     */
    private fun saveProfile(profile: Profile) {
        val editor = profilePrefs.edit()
        
        editor.putString("profileType", profile.type.name)
        editor.putInt("trapTriggerThreshold", profile.trapTriggerThreshold)
        editor.putInt("maxTrapsCount", profile.maxTrapsCount)
        editor.putBoolean("trapDynamicGeneration", profile.trapDynamicGeneration)
        editor.putBoolean("anomalyDetectionEnabled", profile.anomalyDetectionEnabled)
        editor.putBoolean("autoBlockEnabled", profile.autoBlockEnabled)
        editor.putString("scanFrequency", profile.scanFrequency.name)
        editor.putBoolean("alertsEnabled", profile.alertsEnabled)
        editor.putBoolean("decoyFilesEnabled", profile.decoyFilesEnabled)
        editor.putBoolean("cloudSyncEnabled", profile.cloudSyncEnabled)
        editor.putBoolean("threatIntelligenceEnabled", profile.threatIntelligenceEnabled)
        editor.putFloat("anomalyThreshold", profile.anomalyThreshold.toFloat())
        
        editor.apply()
    }
    
    /**
     * Apply the profile settings to the honeypot system
     */
    private fun applyProfile(profile: Profile) {
        // Apply trap sensitivity settings asynchronously
        CoroutineScope(Dispatchers.IO).launch {
            try {
                // If no traps exist or if we should reset traps based on profile,
                // create default traps for the profile
                val activeTraps = cloneDetectionService.getActiveTraps()
                if (activeTraps.isEmpty() || profile.resetExistingTraps) {
                    setupDefaultTrapsForProfile(profile)
                }
                
                // Apply AI Engine settings if available
                aiEngine?.let { engine ->
                    // Update anomaly threshold
                    if (profile.anomalyDetectionEnabled) {
                        // AI engine is controlled by the profile settings
                    } else {
                        // Disable AI monitoring (in a real implementation)
                    }
                }
                
                // Apply trap generation settings if available
                trapGenerator?.let { generator ->
                    // Dynamic trap generation can be enabled/disabled
                    if (profile.trapDynamicGeneration) {
                        // Enable dynamic generation with profile settings
                    } else {
                        // Disable dynamic generation
                    }
                }
                
            } catch (e: Exception) {
                e.printStackTrace()
            }
        }
    }
    
    /**
     * Set up the default traps for a specific profile
     */
    private fun setupDefaultTrapsForProfile(profile: Profile) {
        // Clear existing traps if we're resetting
        if (profile.resetExistingTraps) {
            val activeTraps = cloneDetectionService.getActiveTraps()
            for (trap in activeTraps) {
                cloneDetectionService.removeTrap(trap.id)
            }
        }
        
        // Create profile-specific traps
        when (profile.type) {
            ProfileType.PASSIVE -> {
                // Minimal trap set for passive monitoring
                cloneDetectionService.addTrap(
                    "Basic File Monitor",
                    CloneDetectionService.TrapType.FILE,
                    "secure/credentials.dat",
                    CloneDetectionService.AlertLevel.MEDIUM,
                    "Basic file access monitoring (Passive Profile)"
                )
                
                cloneDetectionService.addTrap(
                    "Primary Network Monitor",
                    CloneDetectionService.TrapType.NETWORK,
                    "8080",
                    CloneDetectionService.AlertLevel.MEDIUM,
                    "Basic network port monitoring (Passive Profile)"
                )
            }
            
            ProfileType.BALANCED -> {
                // Standard trap set for balanced monitoring
                cloneDetectionService.addTrap(
                    "Config File Monitor",
                    CloneDetectionService.TrapType.FILE,
                    "config/settings.json",
                    CloneDetectionService.AlertLevel.MEDIUM,
                    "Configuration file access monitoring (Balanced Profile)"
                )
                
                cloneDetectionService.addTrap(
                    "Credentials Monitor",
                    CloneDetectionService.TrapType.FILE,
                    "secure/credentials.dat",
                    CloneDetectionService.AlertLevel.HIGH,
                    "Sensitive credentials monitoring (Balanced Profile)"
                )
                
                cloneDetectionService.addTrap(
                    "API Gateway Monitor",
                    CloneDetectionService.TrapType.NETWORK,
                    "8080",
                    CloneDetectionService.AlertLevel.MEDIUM,
                    "API gateway monitoring (Balanced Profile)"
                )
                
                cloneDetectionService.addTrap(
                    "System Process Monitor",
                    CloneDetectionService.TrapType.PROCESS,
                    "system_service",
                    CloneDetectionService.AlertLevel.MEDIUM,
                    "System process monitoring (Balanced Profile)"
                )
            }
            
            ProfileType.PARANOID -> {
                // Comprehensive trap set for paranoid monitoring
                
                // File traps
                cloneDetectionService.addTrap(
                    "Config File Monitor",
                    CloneDetectionService.TrapType.FILE,
                    "config/settings.json",
                    CloneDetectionService.AlertLevel.HIGH,
                    "Configuration file access monitoring (Paranoid Profile)"
                )
                
                cloneDetectionService.addTrap(
                    "Credentials Monitor",
                    CloneDetectionService.TrapType.FILE,
                    "secure/credentials.dat",
                    CloneDetectionService.AlertLevel.HIGH,
                    "Sensitive credentials monitoring (Paranoid Profile)"
                )
                
                cloneDetectionService.addTrap(
                    "Keystore Monitor",
                    CloneDetectionService.TrapType.FILE,
                    "secure/app.keystore",
                    CloneDetectionService.AlertLevel.HIGH,
                    "Keystore file monitoring (Paranoid Profile)"
                )
                
                // Network traps
                cloneDetectionService.addTrap(
                    "API Gateway Monitor",
                    CloneDetectionService.TrapType.NETWORK,
                    "8080",
                    CloneDetectionService.AlertLevel.HIGH,
                    "API gateway monitoring (Paranoid Profile)"
                )
                
                cloneDetectionService.addTrap(
                    "Secure API Monitor",
                    CloneDetectionService.TrapType.NETWORK,
                    "443",
                    CloneDetectionService.AlertLevel.HIGH,
                    "Secure API monitoring (Paranoid Profile)"
                )
                
                cloneDetectionService.addTrap(
                    "Database Port Monitor",
                    CloneDetectionService.TrapType.NETWORK,
                    "5432",
                    CloneDetectionService.AlertLevel.HIGH,
                    "Database port monitoring (Paranoid Profile)"
                )
                
                // Process traps
                cloneDetectionService.addTrap(
                    "System Process Monitor",
                    CloneDetectionService.TrapType.PROCESS,
                    "system_service",
                    CloneDetectionService.AlertLevel.HIGH,
                    "System process monitoring (Paranoid Profile)"
                )
                
                cloneDetectionService.addTrap(
                    "Package Manager Monitor",
                    CloneDetectionService.TrapType.PROCESS,
                    "package_manager",
                    CloneDetectionService.AlertLevel.HIGH,
                    "Package manager monitoring (Paranoid Profile)"
                )
                
                // Apply template groups if available
                trapGenerator?.let { generator ->
                    generator.applyTemplateGroup("Network Protection Suite")
                    generator.applyTemplateGroup("File System Guards")
                }
            }
        }
    }
    
    /**
     * Create a passive (low sensitivity) profile
     */
    private fun createPassiveProfile(): Profile {
        return Profile(
            type = ProfileType.PASSIVE,
            name = "Passive Monitoring",
            description = "Minimal security monitoring with few traps and low alerts",
            trapTriggerThreshold = 5,
            maxTrapsCount = 5,
            trapDynamicGeneration = false,
            anomalyDetectionEnabled = false,
            autoBlockEnabled = false,
            scanFrequency = ScanFrequency.LOW,
            alertsEnabled = true,
            decoyFilesEnabled = false,
            cloudSyncEnabled = false,
            threatIntelligenceEnabled = false,
            anomalyThreshold = 0.8,
            resetExistingTraps = true
        )
    }
    
    /**
     * Create a balanced (medium sensitivity) profile
     */
    private fun createBalancedProfile(): Profile {
        return Profile(
            type = ProfileType.BALANCED,
            name = "Balanced Protection",
            description = "Standard security monitoring with moderate traps and alerts",
            trapTriggerThreshold = 3,
            maxTrapsCount = 10,
            trapDynamicGeneration = true,
            anomalyDetectionEnabled = true,
            autoBlockEnabled = false,
            scanFrequency = ScanFrequency.MEDIUM,
            alertsEnabled = true,
            decoyFilesEnabled = true,
            cloudSyncEnabled = true,
            threatIntelligenceEnabled = true,
            anomalyThreshold = 0.7,
            resetExistingTraps = true
        )
    }
    
    /**
     * Create a paranoid (high sensitivity) profile
     */
    private fun createParanoidProfile(): Profile {
        return Profile(
            type = ProfileType.PARANOID,
            name = "Paranoid Security",
            description = "Maximum security monitoring with extensive traps and alerts",
            trapTriggerThreshold = 1,
            maxTrapsCount = 25,
            trapDynamicGeneration = true,
            anomalyDetectionEnabled = true,
            autoBlockEnabled = true,
            scanFrequency = ScanFrequency.HIGH,
            alertsEnabled = true,
            decoyFilesEnabled = true,
            cloudSyncEnabled = true,
            threatIntelligenceEnabled = true,
            anomalyThreshold = 0.6,
            resetExistingTraps = true
        )
    }
    
    /**
     * Get the last time the profile was changed
     */
    fun getProfileChangeTimestamp(): Long {
        return profileChangeTimestamp
    }
    
    /**
     * Data class representing a complete honeypot profile
     */
    data class Profile(
        val type: ProfileType = ProfileType.BALANCED,
        val name: String = "Balanced Protection",
        val description: String = "Standard security monitoring with moderate traps and alerts",
        var trapTriggerThreshold: Int = 3,
        var maxTrapsCount: Int = 10,
        var trapDynamicGeneration: Boolean = true,
        var anomalyDetectionEnabled: Boolean = true,
        var autoBlockEnabled: Boolean = false,
        var scanFrequency: ScanFrequency = ScanFrequency.MEDIUM,
        var alertsEnabled: Boolean = true,
        var decoyFilesEnabled: Boolean = true,
        var cloudSyncEnabled: Boolean = true,
        var threatIntelligenceEnabled: Boolean = true,
        var anomalyThreshold: Double = 0.7,
        var resetExistingTraps: Boolean = false
    )
} 