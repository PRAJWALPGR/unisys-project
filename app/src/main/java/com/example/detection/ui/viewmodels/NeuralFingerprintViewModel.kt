package com.example.detection.ui.viewmodels

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.example.detection.service.NeuralFingerprintService
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch

class NeuralFingerprintViewModel(application: Application) : AndroidViewModel(application) {
    private val neuralFingerprintService = NeuralFingerprintService(application)
    
    private val _appAnalysisState = MutableStateFlow<AppAnalysisState>(AppAnalysisState.Loading)
    val appAnalysisState: StateFlow<AppAnalysisState> = _appAnalysisState
    
    fun refreshAppAnalysis() {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                _appAnalysisState.value = AppAnalysisState.Loading
                neuralFingerprintService.refreshAppAnalysis()
                val appInfoList = neuralFingerprintService.appAnalysisResults.value.map { result ->
                    AppAnalysisInfo(
                        appName = result.appName,
                        packageName = result.packageName,
                        installerStore = result.installerStore,
                        isSystemApp = result.isSystemApp,
                        trustScore = result.trustScore,
                        primaryIssue = result.primaryIssue,
                        dangerousPermissions = emptyList() // We could populate this from the service if needed
                    )
                }
                _appAnalysisState.value = AppAnalysisState.Success(appInfoList)
            } catch (e: Exception) {
                _appAnalysisState.value = AppAnalysisState.Error(e.message ?: "Unknown error")
            }
        }
    }
    
    fun runDeepScan() {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                _appAnalysisState.value = AppAnalysisState.Loading
                // Start the model training process
                neuralFingerprintService.startModelTraining(1.0f)
                // Refresh app analysis after training
                neuralFingerprintService.refreshAppAnalysis()
                
                val appInfoList = neuralFingerprintService.appAnalysisResults.value.map { result ->
                    AppAnalysisInfo(
                        appName = result.appName,
                        packageName = result.packageName,
                        installerStore = result.installerStore,
                        isSystemApp = result.isSystemApp,
                        trustScore = result.trustScore,
                        primaryIssue = result.primaryIssue,
                        dangerousPermissions = emptyList()
                    )
                }
                _appAnalysisState.value = AppAnalysisState.Success(appInfoList)
            } catch (e: Exception) {
                _appAnalysisState.value = AppAnalysisState.Error(e.message ?: "Deep scan failed")
            }
        }
    }
}

sealed class AppAnalysisState {
    object Loading : AppAnalysisState()
    data class Success(val data: List<AppAnalysisInfo>) : AppAnalysisState()
    data class Error(val message: String) : AppAnalysisState()
}

data class AppAnalysisInfo(
    val appName: String,
    val packageName: String,
    val installerStore: String,
    val isSystemApp: Boolean,
    val trustScore: Int,
    val primaryIssue: String = "",
    val dangerousPermissions: List<String> = emptyList()
) 