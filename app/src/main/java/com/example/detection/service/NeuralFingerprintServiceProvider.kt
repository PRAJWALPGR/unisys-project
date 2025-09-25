package com.example.detection.service

/**
 * Interface for providing the NeuralFingerprintService
 * This enables dependency injection and access to the service from various components
 */
interface NeuralFingerprintServiceProvider {
    /**
     * Get the NeuralFingerprintService instance
     * @return The service instance or null if not available
     */
    fun getNeuralFingerprintService(): NeuralFingerprintService?
} 