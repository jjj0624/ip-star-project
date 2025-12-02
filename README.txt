# IP 星伴 (IP Star)

IP 星伴 是一个集成了 Web 端管理系统 与 LLM 大模型智能体 的综合性 IP 商业化解决方案。
项目旨在解决 IP 资产确权难、合同管理混乱、授权渠道匹配效率低等痛点，通过数字化手段连接内部法务运营与外部合作伙伴。

一、核心功能
1. 内控管理端 (Internal Dashboard)
* 资产全景: 数字化管理 IP 图样、权属、商标注册信息及实时收益数据。
* 合同台账: 全生命周期的合同管理，支持 PDF 原件归档、许可期限监控及到期预警。
* 数据驾驶舱: 基于 ECharts 的可视化报表，展示 IP 热度、收益排行及资产分布。
* 智能法务助手: 集成腾讯云 AI，支持一键生成经营分析报表、起草标准合同文档（Word 格式）。

2. 合作伙伴端 (Partner Portal)
* IP 形象库: 沉浸式展示企业优质 IP 资源，支持按商业价值等级（S/A/B/C）检索。
* 成功案例橱窗: 展示过往精彩联名案例，激发合作灵感。
* 智能合作顾问: 集成腾讯云 AI，提供 24/7 的创意策划推荐与合规的费用估算参考。


二、技术栈
* 后端框架: Flask (Python 3.12)
* 数据库: MySQL (SQLAlchemy ORM)
* 前端: Bootstrap 5, Jinja2, ECharts
* AI 集成: 腾讯云智能体平台 (Tencent Cloud AI Agents)
* 文档处理: python-docx (用于自动生成合同)


三、开发与运行 (Local Setup)
已通过pythonanywhere部署至云上操作。

注：部署数据库的SQL代码详见setup.sql