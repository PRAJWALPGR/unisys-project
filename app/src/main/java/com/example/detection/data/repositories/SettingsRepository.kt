package com.example.detection.data.repositories

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.*
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map

private val Context.dataStore: DataStore<Preferences> by preferencesDataStore(name = "settings")

class SettingsRepository(private val context: Context) {

    // Clone Detection settings
    val isCloneDetectionEnabled: Flow<Boolean> = context.dataStore.data
        .map { preferences -> preferences[CLONE_DETECTION_ENABLED] ?: true }
    
    val scanFrequency: Flow<String> = context.dataStore.data
        .map { preferences -> preferences[SCAN_FREQUENCY] ?: "Medium" }
    
    // Network Security settings
    val isNetworkMonitoringEnabled: Flow<Boolean> = context.dataStore.data
        .map { preferences -> preferences[NETWORK_MONITORING_ENABLED] ?: true }
    
    val isMirrorReflectionEnabled: Flow<Boolean> = context.dataStore.data
        .map { preferences -> preferences[MIRROR_REFLECTION_ENABLED] ?: true }
    
    val isPolymorphicResponseEnabled: Flow<Boolean> = context.dataStore.data
        .map { preferences -> preferences[POLYMORPHIC_RESPONSE_ENABLED] ?: true }
    
    // Neural Fingerprint settings
    val isNeuralFingerprintEnabled: Flow<Boolean> = context.dataStore.data
        .map { preferences -> preferences[NEURAL_FINGERPRINT_ENABLED] ?: true }
    
    val isAdaptiveLearningEnabled: Flow<Boolean> = context.dataStore.data
        .map { preferences -> preferences[ADAPTIVE_LEARNING_ENABLED] ?: true }
    
    // Honeypot Traps settings
    val isHoneypotSystemEnabled: Flow<Boolean> = context.dataStore.data
        .map { preferences -> preferences[HONEYPOT_SYSTEM_ENABLED] ?: true }
    
    val isEmotionalDeceptionEnabled: Flow<Boolean> = context.dataStore.data
        .map { preferences -> preferences[EMOTIONAL_DECEPTION_ENABLED] ?: true }
    
    val isPolymorphicHoneypotsEnabled: Flow<Boolean> = context.dataStore.data
        .map { preferences -> preferences[POLYMORPHIC_HONEYPOTS_ENABLED] ?: true }
    
    val isFakeCryptoWalletsEnabled: Flow<Boolean> = context.dataStore.data
        .map { preferences -> preferences[FAKE_CRYPTO_WALLETS_ENABLED] ?: true }
    
    val isInvisibleOverlayTrapsEnabled: Flow<Boolean> = context.dataStore.data
        .map { preferences -> preferences[INVISIBLE_OVERLAY_TRAPS_ENABLED] ?: true }
    
    val isSelfHealingHoneypotsEnabled: Flow<Boolean> = context.dataStore.data
        .map { preferences -> preferences[SELF_HEALING_HONEYPOTS_ENABLED] ?: true }
    
    // Deep Scan settings
    val isDeepScanEnabled: Flow<Boolean> = context.dataStore.data
        .map { preferences -> preferences[DEEP_SCAN_ENABLED] ?: true }
    
    val isRootDetectionEnabled: Flow<Boolean> = context.dataStore.data
        .map { preferences -> preferences[ROOT_DETECTION_ENABLED] ?: true }
    
    val isPackageIntegrityEnabled: Flow<Boolean> = context.dataStore.data
        .map { preferences -> preferences[PACKAGE_INTEGRITY_ENABLED] ?: true }
    
    // Blockchain Verification settings
    val isBlockchainVerificationEnabled: Flow<Boolean> = context.dataStore.data
        .map { preferences -> preferences[BLOCKCHAIN_VERIFICATION_ENABLED] ?: true }
    
    val blockchainSyncFrequency: Flow<String> = context.dataStore.data
        .map { preferences -> preferences[BLOCKCHAIN_SYNC_FREQUENCY] ?: "Daily" }
    
    // Advanced Controls settings
    val isAutoHealingEnabled: Flow<Boolean> = context.dataStore.data
        .map { preferences -> preferences[AUTO_HEALING_ENABLED] ?: true }
    
    val isArThreatVisualizationEnabled: Flow<Boolean> = context.dataStore.data
        .map { preferences -> preferences[AR_THREAT_VISUALIZATION_ENABLED] ?: false }
    
    val isStealthModeEnabled: Flow<Boolean> = context.dataStore.data
        .map { preferences -> preferences[STEALTH_MODE_ENABLED] ?: false }
    
    val isPredictiveThreatWarningsEnabled: Flow<Boolean> = context.dataStore.data
        .map { preferences -> preferences[PREDICTIVE_THREAT_WARNINGS_ENABLED] ?: true }
    
    suspend fun toggleCloneDetection(enabled: Boolean) {
        context.dataStore.edit { preferences ->
            preferences[CLONE_DETECTION_ENABLED] = enabled
        }
    }
    
    suspend fun setScanFrequency(frequency: String) {
        context.dataStore.edit { preferences ->
            preferences[SCAN_FREQUENCY] = frequency
        }
    }
    
    suspend fun toggleNetworkMonitoring(enabled: Boolean) {
        context.dataStore.edit { preferences ->
            preferences[NETWORK_MONITORING_ENABLED] = enabled
        }
    }
    
    suspend fun toggleMirrorReflection(enabled: Boolean) {
        context.dataStore.edit { preferences ->
            preferences[MIRROR_REFLECTION_ENABLED] = enabled
        }
    }
    
    suspend fun togglePolymorphicResponse(enabled: Boolean) {
        context.dataStore.edit { preferences ->
            preferences[POLYMORPHIC_RESPONSE_ENABLED] = enabled
        }
    }
    
    suspend fun toggleNeuralFingerprint(enabled: Boolean) {
        context.dataStore.edit { preferences ->
            preferences[NEURAL_FINGERPRINT_ENABLED] = enabled
        }
    }
    
    suspend fun toggleAdaptiveLearning(enabled: Boolean) {
        context.dataStore.edit { preferences ->
            preferences[ADAPTIVE_LEARNING_ENABLED] = enabled
        }
    }
    
    suspend fun toggleHoneypotSystem(enabled: Boolean) {
        context.dataStore.edit { preferences ->
            preferences[HONEYPOT_SYSTEM_ENABLED] = enabled
        }
    }
    
    suspend fun toggleEmotionalDeception(enabled: Boolean) {
        context.dataStore.edit { preferences ->
            preferences[EMOTIONAL_DECEPTION_ENABLED] = enabled
        }
    }
    
    suspend fun togglePolymorphicHoneypots(enabled: Boolean) {
        context.dataStore.edit { preferences ->
            preferences[POLYMORPHIC_HONEYPOTS_ENABLED] = enabled
        }
    }
    
    suspend fun toggleFakeCryptoWallets(enabled: Boolean) {
        context.dataStore.edit { preferences ->
            preferences[FAKE_CRYPTO_WALLETS_ENABLED] = enabled
        }
    }
    
    suspend fun toggleInvisibleOverlayTraps(enabled: Boolean) {
        context.dataStore.edit { preferences ->
            preferences[INVISIBLE_OVERLAY_TRAPS_ENABLED] = enabled
        }
    }
    
    suspend fun toggleSelfHealingHoneypots(enabled: Boolean) {
        context.dataStore.edit { preferences ->
            preferences[SELF_HEALING_HONEYPOTS_ENABLED] = enabled
        }
    }
    
    suspend fun toggleDeepScan(enabled: Boolean) {
        context.dataStore.edit { preferences ->
            preferences[DEEP_SCAN_ENABLED] = enabled
        }
    }
    
    suspend fun toggleRootDetection(enabled: Boolean) {
        context.dataStore.edit { preferences ->
            preferences[ROOT_DETECTION_ENABLED] = enabled
        }
    }
    
    suspend fun togglePackageIntegrity(enabled: Boolean) {
        context.dataStore.edit { preferences ->
            preferences[PACKAGE_INTEGRITY_ENABLED] = enabled
        }
    }
    
    suspend fun toggleBlockchainVerification(enabled: Boolean) {
        context.dataStore.edit { preferences ->
            preferences[BLOCKCHAIN_VERIFICATION_ENABLED] = enabled
        }
    }
    
    suspend fun setBlockchainSyncFrequency(frequency: String) {
        context.dataStore.edit { preferences ->
            preferences[BLOCKCHAIN_SYNC_FREQUENCY] = frequency
        }
    }
    
    suspend fun toggleAutoHealing(enabled: Boolean) {
        context.dataStore.edit { preferences ->
            preferences[AUTO_HEALING_ENABLED] = enabled
        }
    }
    
    suspend fun toggleArThreatVisualization(enabled: Boolean) {
        context.dataStore.edit { preferences ->
            preferences[AR_THREAT_VISUALIZATION_ENABLED] = enabled
        }
    }
    
    suspend fun toggleStealthMode(enabled: Boolean) {
        context.dataStore.edit { preferences ->
            preferences[STEALTH_MODE_ENABLED] = enabled
        }
    }
    
    suspend fun togglePredictiveThreatWarnings(enabled: Boolean) {
        context.dataStore.edit { preferences ->
            preferences[PREDICTIVE_THREAT_WARNINGS_ENABLED] = enabled
        }
    }
    
    companion object {
        private val CLONE_DETECTION_ENABLED = booleanPreferencesKey("clone_detection_enabled")
        private val SCAN_FREQUENCY = stringPreferencesKey("scan_frequency")
        
        private val NETWORK_MONITORING_ENABLED = booleanPreferencesKey("network_monitoring_enabled")
        private val MIRROR_REFLECTION_ENABLED = booleanPreferencesKey("mirror_reflection_enabled")
        private val POLYMORPHIC_RESPONSE_ENABLED = booleanPreferencesKey("polymorphic_response_enabled")
        
        private val NEURAL_FINGERPRINT_ENABLED = booleanPreferencesKey("neural_fingerprint_enabled")
        private val ADAPTIVE_LEARNING_ENABLED = booleanPreferencesKey("adaptive_learning_enabled")
        
        private val HONEYPOT_SYSTEM_ENABLED = booleanPreferencesKey("honeypot_system_enabled")
        private val EMOTIONAL_DECEPTION_ENABLED = booleanPreferencesKey("emotional_deception_enabled")
        private val POLYMORPHIC_HONEYPOTS_ENABLED = booleanPreferencesKey("polymorphic_honeypots_enabled")
        private val FAKE_CRYPTO_WALLETS_ENABLED = booleanPreferencesKey("fake_crypto_wallets_enabled")
        private val INVISIBLE_OVERLAY_TRAPS_ENABLED = booleanPreferencesKey("invisible_overlay_traps_enabled")
        private val SELF_HEALING_HONEYPOTS_ENABLED = booleanPreferencesKey("self_healing_honeypots_enabled")
        
        private val DEEP_SCAN_ENABLED = booleanPreferencesKey("deep_scan_enabled")
        private val ROOT_DETECTION_ENABLED = booleanPreferencesKey("root_detection_enabled")
        private val PACKAGE_INTEGRITY_ENABLED = booleanPreferencesKey("package_integrity_enabled")
        
        private val BLOCKCHAIN_VERIFICATION_ENABLED = booleanPreferencesKey("blockchain_verification_enabled")
        private val BLOCKCHAIN_SYNC_FREQUENCY = stringPreferencesKey("blockchain_sync_frequency")
        
        private val AUTO_HEALING_ENABLED = booleanPreferencesKey("auto_healing_enabled")
        private val AR_THREAT_VISUALIZATION_ENABLED = booleanPreferencesKey("ar_threat_visualization_enabled")
        private val STEALTH_MODE_ENABLED = booleanPreferencesKey("stealth_mode_enabled")
        private val PREDICTIVE_THREAT_WARNINGS_ENABLED = booleanPreferencesKey("predictive_threat_warnings_enabled")
    }
} 