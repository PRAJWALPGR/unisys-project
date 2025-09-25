package com.example.detection.ui.viewmodels

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.example.detection.data.repositories.SettingsRepository
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

class SettingsViewModel(application: Application) : AndroidViewModel(application) {
    
    private val repository = SettingsRepository(application)
    
    // Clone Detection settings
    val isCloneDetectionEnabled = repository.isCloneDetectionEnabled
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), true)
    
    val scanFrequency = repository.scanFrequency
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), "Medium")
    
    // Network Security settings
    val isNetworkMonitoringEnabled = repository.isNetworkMonitoringEnabled
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), true)
    
    val isMirrorReflectionEnabled = repository.isMirrorReflectionEnabled
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), true)
    
    val isPolymorphicResponseEnabled = repository.isPolymorphicResponseEnabled
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), true)
    
    // Neural Fingerprint settings
    val isNeuralFingerprintEnabled = repository.isNeuralFingerprintEnabled
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), true)
    
    val isAdaptiveLearningEnabled = repository.isAdaptiveLearningEnabled
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), true)
    
    // Honeypot Traps settings
    val isHoneypotSystemEnabled = repository.isHoneypotSystemEnabled
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), true)
    
    val isEmotionalDeceptionEnabled = repository.isEmotionalDeceptionEnabled
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), true)
    
    val isPolymorphicHoneypotsEnabled = repository.isPolymorphicHoneypotsEnabled
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), true)
    
    val isFakeCryptoWalletsEnabled = repository.isFakeCryptoWalletsEnabled
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), true)
    
    val isInvisibleOverlayTrapsEnabled = repository.isInvisibleOverlayTrapsEnabled
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), true)
    
    val isSelfHealingHoneypotsEnabled = repository.isSelfHealingHoneypotsEnabled
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), true)
    
    // Deep Scan settings
    val isDeepScanEnabled = repository.isDeepScanEnabled
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), true)
    
    val isRootDetectionEnabled = repository.isRootDetectionEnabled
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), true)
    
    val isPackageIntegrityEnabled = repository.isPackageIntegrityEnabled
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), true)
    
    // Blockchain Verification settings
    val isBlockchainVerificationEnabled = repository.isBlockchainVerificationEnabled
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), true)
    
    val blockchainSyncFrequency = repository.blockchainSyncFrequency
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), "Daily")
    
    // Advanced Controls settings
    val isAutoHealingEnabled = repository.isAutoHealingEnabled
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), true)
    
    val isArThreatVisualizationEnabled = repository.isArThreatVisualizationEnabled
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), false)
    
    val isStealthModeEnabled = repository.isStealthModeEnabled
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), false)
    
    val isPredictiveThreatWarningsEnabled = repository.isPredictiveThreatWarningsEnabled
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), true)
    
    // Toggle functions for Clone Detection settings
    fun toggleCloneDetection(enabled: Boolean) {
        viewModelScope.launch {
            repository.toggleCloneDetection(enabled)
        }
    }
    
    fun setScanFrequency(frequency: String) {
        viewModelScope.launch {
            repository.setScanFrequency(frequency)
        }
    }
    
    // Toggle functions for Network Security settings
    fun toggleNetworkMonitoring(enabled: Boolean) {
        viewModelScope.launch {
            repository.toggleNetworkMonitoring(enabled)
        }
    }
    
    fun toggleMirrorReflection(enabled: Boolean) {
        viewModelScope.launch {
            repository.toggleMirrorReflection(enabled)
        }
    }
    
    fun togglePolymorphicResponse(enabled: Boolean) {
        viewModelScope.launch {
            repository.togglePolymorphicResponse(enabled)
        }
    }
    
    // Toggle functions for Neural Fingerprint settings
    fun toggleNeuralFingerprint(enabled: Boolean) {
        viewModelScope.launch {
            repository.toggleNeuralFingerprint(enabled)
        }
    }
    
    fun toggleAdaptiveLearning(enabled: Boolean) {
        viewModelScope.launch {
            repository.toggleAdaptiveLearning(enabled)
        }
    }
    
    // Toggle functions for Honeypot Traps settings
    fun toggleHoneypotSystem(enabled: Boolean) {
        viewModelScope.launch {
            repository.toggleHoneypotSystem(enabled)
        }
    }
    
    fun toggleEmotionalDeception(enabled: Boolean) {
        viewModelScope.launch {
            repository.toggleEmotionalDeception(enabled)
        }
    }
    
    fun togglePolymorphicHoneypots(enabled: Boolean) {
        viewModelScope.launch {
            repository.togglePolymorphicHoneypots(enabled)
        }
    }
    
    fun toggleFakeCryptoWallets(enabled: Boolean) {
        viewModelScope.launch {
            repository.toggleFakeCryptoWallets(enabled)
        }
    }
    
    fun toggleInvisibleOverlayTraps(enabled: Boolean) {
        viewModelScope.launch {
            repository.toggleInvisibleOverlayTraps(enabled)
        }
    }
    
    fun toggleSelfHealingHoneypots(enabled: Boolean) {
        viewModelScope.launch {
            repository.toggleSelfHealingHoneypots(enabled)
        }
    }
    
    // Toggle functions for Deep Scan settings
    fun toggleDeepScan(enabled: Boolean) {
        viewModelScope.launch {
            repository.toggleDeepScan(enabled)
        }
    }
    
    fun toggleRootDetection(enabled: Boolean) {
        viewModelScope.launch {
            repository.toggleRootDetection(enabled)
        }
    }
    
    fun togglePackageIntegrity(enabled: Boolean) {
        viewModelScope.launch {
            repository.togglePackageIntegrity(enabled)
        }
    }
    
    // Toggle functions for Blockchain Verification settings
    fun toggleBlockchainVerification(enabled: Boolean) {
        viewModelScope.launch {
            repository.toggleBlockchainVerification(enabled)
        }
    }
    
    fun setBlockchainSyncFrequency(frequency: String) {
        viewModelScope.launch {
            repository.setBlockchainSyncFrequency(frequency)
        }
    }
    
    // Toggle functions for Advanced Controls settings
    fun toggleAutoHealing(enabled: Boolean) {
        viewModelScope.launch {
            repository.toggleAutoHealing(enabled)
        }
    }
    
    fun toggleArThreatVisualization(enabled: Boolean) {
        viewModelScope.launch {
            repository.toggleArThreatVisualization(enabled)
        }
    }
    
    fun toggleStealthMode(enabled: Boolean) {
        viewModelScope.launch {
            repository.toggleStealthMode(enabled)
        }
    }
    
    fun togglePredictiveThreatWarnings(enabled: Boolean) {
        viewModelScope.launch {
            repository.togglePredictiveThreatWarnings(enabled)
        }
    }
} 