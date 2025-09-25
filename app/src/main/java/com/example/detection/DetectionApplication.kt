package com.example.detection

import android.app.Application
import android.util.Log
import com.example.detection.service.NeuralFingerprintService
import com.example.detection.service.NeuralFingerprintServiceProvider

/**
 * Main Application class for the Detection application
 * Implements NeuralFingerprintServiceProvider to enable service access
 */
class DetectionApplication : Application(), NeuralFingerprintServiceProvider {
    
    private var neuralFingerprintService: NeuralFingerprintService? = null
    private val TAG = "DetectionApplication"
    
    override fun onCreate() {
        super.onCreate()
        
        try {
            // Initialize the NeuralFingerprintService
            neuralFingerprintService = NeuralFingerprintService(applicationContext)
        } catch (e: Exception) {
            // Log the error but don't crash the app
            Log.e(TAG, "Error initializing NeuralFingerprintService: ${e.message}")
            e.printStackTrace()
        }
    }
    
    /**
     * Provides access to the NeuralFingerprintService instance
     */
    override fun getNeuralFingerprintService(): NeuralFingerprintService? {
        return neuralFingerprintService
    }
} 