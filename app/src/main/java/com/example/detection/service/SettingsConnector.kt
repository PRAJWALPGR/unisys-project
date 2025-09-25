package com.example.detection.service

import android.content.Context
import androidx.lifecycle.LifecycleCoroutineScope
import com.example.detection.data.repositories.SettingsRepository
import com.example.detection.honeypot.emotiontrap.EmotionalDeceptionManager
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch

/**
 * SettingsConnector observes settings changes and applies them to corresponding services.
 * This ensures that toggling a setting in the Settings screen affects the actual functionality.
 */
class SettingsConnector(
    private val context: Context,
    private val lifecycleScope: LifecycleCoroutineScope,
    private val cloneDetectionService: CloneDetectionService,
    private val networkMonitorService: NetworkMonitorService,
    private val neuralFingerprintService: NeuralFingerprintService,
    private val networkMirrorReflectionService: NetworkMirrorReflectionService,
    private val deepScanService: DeepScanService,
    private val blockchainScanService: BlockchainScanService,
    private val emotionalDeceptionManager: EmotionalDeceptionManager
) {
    private val settingsRepository = SettingsRepository(context)

    fun initialize() {
        observeCloneDetectionSettings()
        observeNetworkSecuritySettings()
        observeNeuralFingerprintSettings()
        observeHoneypotSettings()
        observeDeepScanSettings()
        observeBlockchainSettings()
        observeAdvancedSettings()
    }

    private fun observeCloneDetectionSettings() {
        lifecycleScope.launch {
            settingsRepository.isCloneDetectionEnabled.collect { enabled ->
                cloneDetectionService.setEnabled(enabled)
            }
        }

        lifecycleScope.launch {
            settingsRepository.scanFrequency.collect { frequency ->
                when (frequency) {
                    "Low" -> cloneDetectionService.setScanFrequency(CloneDetectionService.ScanFrequency.LOW)
                    "Medium" -> cloneDetectionService.setScanFrequency(CloneDetectionService.ScanFrequency.MEDIUM)
                    "High" -> cloneDetectionService.setScanFrequency(CloneDetectionService.ScanFrequency.HIGH)
                }
            }
        }
    }

    private fun observeNetworkSecuritySettings() {
        lifecycleScope.launch {
            settingsRepository.isNetworkMonitoringEnabled.collect { enabled ->
                networkMonitorService.setEnabled(enabled)
            }
        }

        lifecycleScope.launch {
            settingsRepository.isMirrorReflectionEnabled.collect { enabled ->
                networkMirrorReflectionService.setMirrorReflectionEnabled(enabled)
            }
        }

        lifecycleScope.launch {
            settingsRepository.isPolymorphicResponseEnabled.collect { enabled ->
                networkMirrorReflectionService.setPolymorphicResponseEnabled(enabled)
            }
        }
    }

    private fun observeNeuralFingerprintSettings() {
        lifecycleScope.launch {
            settingsRepository.isNeuralFingerprintEnabled.collect { enabled ->
                neuralFingerprintService.setEnabled(enabled)
            }
        }

        lifecycleScope.launch {
            settingsRepository.isAdaptiveLearningEnabled.collect { enabled ->
                neuralFingerprintService.setAdaptiveLearningEnabled(enabled)
            }
        }
    }

    private fun observeHoneypotSettings() {
        lifecycleScope.launch {
            settingsRepository.isHoneypotSystemEnabled.collect { enabled ->
                // Enable/disable the overall honeypot system
                cloneDetectionService.setHoneypotTrapsEnabled(enabled)
            }
        }

        lifecycleScope.launch {
            settingsRepository.isEmotionalDeceptionEnabled.collect { enabled ->
                emotionalDeceptionManager.setEnabled(enabled)
            }
        }

        lifecycleScope.launch {
            settingsRepository.isPolymorphicHoneypotsEnabled.collect { enabled ->
                cloneDetectionService.setPolymorphicHoneypotsEnabled(enabled)
            }
        }

        lifecycleScope.launch {
            settingsRepository.isFakeCryptoWalletsEnabled.collect { enabled ->
                cloneDetectionService.setFakeCryptoWalletsEnabled(enabled)
            }
        }

        lifecycleScope.launch {
            settingsRepository.isInvisibleOverlayTrapsEnabled.collect { enabled ->
                cloneDetectionService.setInvisibleOverlayTrapsEnabled(enabled)
            }
        }

        lifecycleScope.launch {
            settingsRepository.isSelfHealingHoneypotsEnabled.collect { enabled ->
                cloneDetectionService.setSelfHealingHoneypotsEnabled(enabled)
            }
        }
    }

    private fun observeDeepScanSettings() {
        lifecycleScope.launch {
            settingsRepository.isDeepScanEnabled.collect { enabled ->
                deepScanService.setEnabled(enabled)
            }
        }

        lifecycleScope.launch {
            settingsRepository.isRootDetectionEnabled.collect { enabled ->
                deepScanService.setRootDetectionEnabled(enabled)
            }
        }

        lifecycleScope.launch {
            settingsRepository.isPackageIntegrityEnabled.collect { enabled ->
                deepScanService.setPackageIntegrityVerificationEnabled(enabled)
            }
        }
    }

    private fun observeBlockchainSettings() {
        lifecycleScope.launch {
            settingsRepository.isBlockchainVerificationEnabled.collect { enabled ->
                blockchainScanService.setEnabled(enabled)
            }
        }

        lifecycleScope.launch {
            settingsRepository.blockchainSyncFrequency.collect { frequency ->
                when (frequency) {
                    "Manual" -> blockchainScanService.setSyncFrequency(BlockchainScanService.SyncFrequency.MANUAL)
                    "Hourly" -> blockchainScanService.setSyncFrequency(BlockchainScanService.SyncFrequency.HOURLY)
                    "Daily" -> blockchainScanService.setSyncFrequency(BlockchainScanService.SyncFrequency.DAILY)
                }
            }
        }
    }

    private fun observeAdvancedSettings() {
        lifecycleScope.launch {
            settingsRepository.isAutoHealingEnabled.collect { enabled ->
                // Apply auto-healing setting
                deepScanService.setAutoHealingEnabled(enabled)
            }
        }

        lifecycleScope.launch {
            settingsRepository.isArThreatVisualizationEnabled.collect { enabled ->
                // Apply AR visualization setting
                cloneDetectionService.setArThreatVisualizationEnabled(enabled)
            }
        }

        lifecycleScope.launch {
            settingsRepository.isStealthModeEnabled.collect { enabled ->
                // Apply stealth mode to all services
                cloneDetectionService.setStealthModeEnabled(enabled)
                networkMonitorService.setStealthModeEnabled(enabled)
                neuralFingerprintService.setStealthModeEnabled(enabled)
                networkMirrorReflectionService.setStealthModeEnabled(enabled)
                deepScanService.setStealthModeEnabled(enabled)
            }
        }

        lifecycleScope.launch {
            settingsRepository.isPredictiveThreatWarningsEnabled.collect { enabled ->
                // Apply predictive warnings setting
                cloneDetectionService.setPredictiveThreatWarningsEnabled(enabled)
            }
        }
    }

    // Helper method to apply initial settings to all services when app starts
    suspend fun applyInitialSettings() {
        // Clone Detection
        val isCloneDetectionEnabled = settingsRepository.isCloneDetectionEnabled.first()
        cloneDetectionService.setEnabled(isCloneDetectionEnabled)
        
        val scanFrequency = settingsRepository.scanFrequency.first()
        when (scanFrequency) {
            "Low" -> cloneDetectionService.setScanFrequency(CloneDetectionService.ScanFrequency.LOW)
            "Medium" -> cloneDetectionService.setScanFrequency(CloneDetectionService.ScanFrequency.MEDIUM)
            "High" -> cloneDetectionService.setScanFrequency(CloneDetectionService.ScanFrequency.HIGH)
        }
        
        // Network Security
        networkMonitorService.setEnabled(settingsRepository.isNetworkMonitoringEnabled.first())
        networkMirrorReflectionService.setMirrorReflectionEnabled(settingsRepository.isMirrorReflectionEnabled.first())
        networkMirrorReflectionService.setPolymorphicResponseEnabled(settingsRepository.isPolymorphicResponseEnabled.first())
        
        // Neural Fingerprint
        neuralFingerprintService.setEnabled(settingsRepository.isNeuralFingerprintEnabled.first())
        neuralFingerprintService.setAdaptiveLearningEnabled(settingsRepository.isAdaptiveLearningEnabled.first())
        
        // Honeypot
        cloneDetectionService.setHoneypotTrapsEnabled(settingsRepository.isHoneypotSystemEnabled.first())
        emotionalDeceptionManager.setEnabled(settingsRepository.isEmotionalDeceptionEnabled.first())
        cloneDetectionService.setPolymorphicHoneypotsEnabled(settingsRepository.isPolymorphicHoneypotsEnabled.first())
        cloneDetectionService.setFakeCryptoWalletsEnabled(settingsRepository.isFakeCryptoWalletsEnabled.first())
        cloneDetectionService.setInvisibleOverlayTrapsEnabled(settingsRepository.isInvisibleOverlayTrapsEnabled.first())
        cloneDetectionService.setSelfHealingHoneypotsEnabled(settingsRepository.isSelfHealingHoneypotsEnabled.first())
        
        // Deep Scan
        deepScanService.setEnabled(settingsRepository.isDeepScanEnabled.first())
        deepScanService.setRootDetectionEnabled(settingsRepository.isRootDetectionEnabled.first())
        deepScanService.setPackageIntegrityVerificationEnabled(settingsRepository.isPackageIntegrityEnabled.first())
        
        // Blockchain
        blockchainScanService.setEnabled(settingsRepository.isBlockchainVerificationEnabled.first())
        when (settingsRepository.blockchainSyncFrequency.first()) {
            "Manual" -> blockchainScanService.setSyncFrequency(BlockchainScanService.SyncFrequency.MANUAL)
            "Hourly" -> blockchainScanService.setSyncFrequency(BlockchainScanService.SyncFrequency.HOURLY)
            "Daily" -> blockchainScanService.setSyncFrequency(BlockchainScanService.SyncFrequency.DAILY)
        }
        
        // Advanced
        deepScanService.setAutoHealingEnabled(settingsRepository.isAutoHealingEnabled.first())
        cloneDetectionService.setArThreatVisualizationEnabled(settingsRepository.isArThreatVisualizationEnabled.first())
        
        val isStealthMode = settingsRepository.isStealthModeEnabled.first()
        cloneDetectionService.setStealthModeEnabled(isStealthMode)
        networkMonitorService.setStealthModeEnabled(isStealthMode)
        neuralFingerprintService.setStealthModeEnabled(isStealthMode)
        networkMirrorReflectionService.setStealthModeEnabled(isStealthMode)
        deepScanService.setStealthModeEnabled(isStealthMode)
        
        cloneDetectionService.setPredictiveThreatWarningsEnabled(settingsRepository.isPredictiveThreatWarningsEnabled.first())
    }
} 