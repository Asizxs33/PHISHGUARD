import axios from 'axios'

const API_BASE = import.meta.env.VITE_API_URL || '/api'
export const API_BASE_URL = API_BASE

const api = axios.create({
    baseURL: API_BASE,
    headers: {
        'Content-Type': 'application/json'
    }
})

export const analyzeUrl = async (url) => {
    const response = await api.post('/analyze-url', { url })
    return response.data
}

export const analyzePhone = async (phone) => {
    const response = await api.post('/analyze-phone', { phone })
    return response.data
}


export const analyzeEmail = async (subject, body, sender) => {
    const response = await api.post('/analyze-email', { subject, body, sender })
    return response.data
}

export const analyzeQr = async (file) => {
    const formData = new FormData()
    formData.append('file', file)
    const response = await api.post('/analyze-qr', formData, {
        headers: { 'Content-Type': 'multipart/form-data' }
    })
    return response.data
}

export const analyzeImage = async (file) => {
    const formData = new FormData()
    formData.append('file', file)
    const response = await api.post('/analyze-image', formData, {
        headers: { 'Content-Type': 'multipart/form-data' }
    })
    return response.data
}

export const analyzeAudio = async (file) => {
    const formData = new FormData()
    formData.append('file', file)
    const response = await api.post('/analyze-audio', formData, {
        headers: { 'Content-Type': 'multipart/form-data' }
    })
    return response.data
}

export const getHistory = async (limit = 50, type = null) => {
    const params = { limit }
    if (type) params.type = type
    const response = await api.get('/history', { params })
    return response.data
}

export const getStats = async () => {
    const response = await api.get('/stats')
    return response.data
}

export const sendChatMessage = async (message) => {
    const response = await api.post('/chat', { message })
    return response.data
}

export const getChatSuggestions = async () => {
    const response = await api.get('/chat/suggestions')
    return response.data
}

export default api
