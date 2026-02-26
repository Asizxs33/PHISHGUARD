import { useState, useEffect } from 'react'
import axios from 'axios'
import api from '../api'

// Leaflet
import { MapContainer, TileLayer, Marker, Popup } from 'react-leaflet'
import 'leaflet/dist/leaflet.css'
import L from 'leaflet'

// Fix Default Leaflet Icon Issue in React
import iconMarker from 'leaflet/dist/images/marker-icon.png'
import iconRetina from 'leaflet/dist/images/marker-icon-2x.png'
import iconShadow from 'leaflet/dist/images/marker-shadow.png'

const customIcon = L.icon({
    iconRetinaUrl: iconRetina,
    iconUrl: iconMarker,
    shadowUrl: iconShadow,
    iconSize: [25, 41],
    iconAnchor: [12, 41],
    popupAnchor: [1, -34],
    tooltipAnchor: [16, -28],
    shadowSize: [41, 41]
});
L.Marker.prototype.options.icon = customIcon;


export default function ThreatIntel() {
    const [domains, setDomains] = useState([])
    const [loading, setLoading] = useState(true)

    useEffect(() => {
        fetchDomains()
    }, [])

    const fetchDomains = async () => {
        try {
            setLoading(true)
            const res = await api.get(`/dangerous-domains?limit=50`)
            setDomains(res.data.dangerous_domains || [])
        } catch (error) {
            console.error("Failed to fetch dangerous domains", error)
        } finally {
            setLoading(false)
        }
    }

    const downloadReport = (domain) => {
        // Since api.defaults.baseURL already points to backend, we create absolute URL
        const base = (api.defaults.baseURL || '').replace(/\/$/, '');
        window.open(`${base}/admin/forensics/${domain}/report`, '_blank')
    }

    const downloadAllDomainsCSV = () => {
        const base = (api.defaults.baseURL || '').replace(/\/$/, '');
        window.open(`${base}/dangerous-domains/download`, '_blank')
    }

    return (
        <div className="space-y-6">
            <header>
                <div className="flex items-center gap-3 mb-2">
                    <div className="w-10 h-10 rounded-xl bg-red-500/10 border border-red-500/20 flex items-center justify-center text-red-500">
                        🛡️
                    </div>
                    <div>
                        <h1 className="text-2xl font-bold text-white">Қауіпсіздік Басқармасы (МВД)</h1>
                        <p className="text-sm text-slate-400">Digital Forensics & Threat Intelligence Dashboard</p>
                    </div>
                </div>
                <p className="text-sm text-slate-500">
                    Автоматизированный сбор криминалистических данных по выявленным фишинговым сайтам и мошенническим ресурсам.
                    Используется для генерации рапортов для приобщения к уголовному делу.
                </p>
            </header>

            <div className="glass-panel p-6">
                <div className="flex items-center justify-between mb-6">
                    <h2 className="text-lg font-semibold text-white">Выявленные Угрозы (Dangerous Domains)</h2>
                    <div className="flex items-center gap-2">
                        <button onClick={downloadAllDomainsCSV} className="px-4 py-2 text-xs bg-red-600 hover:bg-red-700 text-white rounded-lg transition-colors font-semibold flexItems-center gap-2">
                            ⬇️ Скачать общую базу (CSV)
                        </button>
                        <button onClick={fetchDomains} className="btn-secondary px-4 py-2 text-xs">
                            Жаңарту (Refresh)
                        </button>
                    </div>
                </div>

                {loading ? (
                    <div className="text-center py-10 text-slate-500 font-mono text-sm animate-pulse">
                        [ SYSTEM SCANNING DATABASE... ]
                    </div>
                ) : domains.length === 0 ? (
                    <div className="text-center py-10 text-slate-500">
                        Деректер табылмады (No data found)
                    </div>
                ) : (
                    <div className="overflow-x-auto">
                        <table className="w-full text-sm text-left">
                            <thead className="text-xs text-slate-400 uppercase bg-slate-800/50 border-y border-slate-700">
                                <tr>
                                    <th className="px-6 py-4">Домен</th>
                                    <th className="px-6 py-4">Уровень Угрозы</th>
                                    <th className="px-6 py-4">IP / Локация</th>
                                    <th className="px-6 py-4">Forensics (Geo & ISP)</th>
                                    <th className="px-6 py-4 text-right">Действие</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-slate-800/50">
                                {domains.map((item) => {
                                    let forensics = {}
                                    try {
                                        if (item.forensics_data) forensics = JSON.parse(item.forensics_data)
                                    } catch (e) { }

                                    const ip = forensics.ip_address || 'Pending...'
                                    const geo = forensics.geo_location || {}
                                    const locString = geo.country ? `${geo.city || ''}, ${geo.country}` : 'Pending...'
                                    const isp = geo.isp || ''

                                    return (
                                        <tr key={item.id} className="hover:bg-white/[0.02] transition-colors">
                                            <td className="px-6 py-4 font-mono text-red-400">
                                                {item.domain}
                                            </td>
                                            <td className="px-6 py-4">
                                                <span className="px-2 py-1 rounded-md bg-red-500/10 text-red-500 border border-red-500/20 text-xs font-bold uppercase tracking-wider">
                                                    {item.risk_level || 'CRITICAL'}
                                                </span>
                                            </td>
                                            <td className="px-6 py-4">
                                                <div className="text-slate-300 font-mono text-xs">{ip}</div>
                                                <div className="text-slate-500 text-[0.65rem] truncate max-w-[150px]">{locString}</div>
                                            </td>
                                            <td className="px-6 py-4">
                                                <div className="text-slate-400 text-xs truncate max-w-[200px]">{isp || 'No ISP data'}</div>
                                            </td>
                                            <td className="px-6 py-4 text-right">
                                                <button
                                                    onClick={() => downloadReport(item.domain)}
                                                    className="px-3 py-1.5 rounded-lg bg-indigo-500/10 hover:bg-indigo-500/20 text-indigo-400 border border-indigo-500/20 text-xs transition-colors whitespace-nowrap"
                                                >
                                                    📄 PDF/TXT Рапорт
                                                </button>
                                            </td>
                                        </tr>
                                    )
                                })}
                            </tbody>
                        </table>
                    </div>
                )}
            </div>

            {/* Map Section */}
            <div className="glass-panel p-6">
                <h2 className="text-lg font-semibold text-white mb-4">Карта Угроз (Global Map)</h2>
                <div className="h-[400px] w-full rounded-xl overflow-hidden border border-slate-700">
                    <MapContainer center={[48.0196, 66.9237]} zoom={3} scrollWheelZoom={false} className="h-full w-full bg-slate-900">
                        <TileLayer
                            attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
                            url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
                        />
                        {domains.map((item) => {
                            let forensics = {}
                            try {
                                if (item.forensics_data) forensics = JSON.parse(item.forensics_data)
                            } catch (e) { }

                            const geo = forensics.geo_location || {}
                            if (geo.lat && geo.lon) {
                                return (
                                    <Marker key={item.id} position={[geo.lat, geo.lon]}>
                                        <Popup>
                                            <div className="text-sm">
                                                <strong className="text-red-600 block mb-1 font-mono">{item.domain}</strong>
                                                <span className="block italic text-slate-500">{forensics.ip_address}</span>
                                                <span className="block mt-1 font-semibold">{item.risk_level || 'CRITICAL'}</span>
                                            </div>
                                        </Popup>
                                    </Marker>
                                )
                            }
                            return null
                        })}
                    </MapContainer>
                </div>
            </div>

        </div>
    )
}
