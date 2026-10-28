// 자산·취약점 가상 데이터와 숫자 버전 판정 로직. 실제 CVE 정보가 아닙니다.
const uid=()=>Array.from(crypto.getRandomValues(new Uint8Array(16)),v=>v.toString(16).padStart(2,'0')).join('');

function normalizeAssets(assets){
	const departmentByAsset={
		'SYS-001':'민원서비스과',
		'SYS-002':'재난대응과',
		'SYS-003':'정보보안과',
		'SYS-004':'데이터분석과',
		'SYS-005':'문서정보과'
	};
	return assets.map(asset=>{
		asset.department=asset.department||departmentByAsset[asset.id]||asset.org||'';
		delete asset.org;
		Object.defineProperty(asset,'org',{configurable:true,get(){return this.department},set(value){this.department=value}});
		return asset;
	});
}

const seed=()=>({assets:[
	{id:'SYS-001',department:'민원서비스과',name:'민원행정 포털',lang:'Java',product:'Demo WAS',version:'9.0.4',owner:'시스템 담당 A',exposed:true,critical:'상',updated:'2026-10-28'},
	{id:'SYS-002',department:'재난대응과',name:'재난상황 관리시스템',lang:'Python',product:'Demo Framework',version:'3.2.1',owner:'시스템 담당 B',exposed:true,critical:'상',updated:'2026-10-28'},
	{id:'SYS-003',department:'정보보안과',name:'내부 업무지원시스템',lang:'Java',product:'Demo WAS',version:'9.0.12',owner:'시스템 담당 C',exposed:false,critical:'중',updated:'2026-10-28'},
	{id:'SYS-004',department:'데이터분석과',name:'데이터 분석 플랫폼',lang:'Python',product:'Demo Framework',version:'',owner:'',exposed:false,critical:'중',updated:'2026-09-01'},
	{id:'SYS-005',department:'문서정보과',name:'문서유통 서비스',lang:'JavaScript',product:'Demo Runtime',version:'20.1.0',owner:'시스템 담당 D',exposed:false,critical:'중',updated:'2026-10-28'},
	{id:'SYS-006',department:'홍보소통과',name:'공개자료 관리 포털',lang:'PHP',product:'PHP',version:'8.2.34',owner:'시스템 담당 E',exposed:true,critical:'상',updated:'2026-10-28'},
	{id:'SYS-007',department:'민원연계과',name:'민원연계 API',lang:'PHP',product:'Demo WAS',version:'9.0.12',owner:'시스템 담당 F',exposed:true,critical:'상',updated:'2026-10-28'},
	{id:'SYS-008',department:'공공데이터과',name:'공공데이터 제공 서비스',lang:'Java',product:'Apache Tomcat',version:'11.0.22',owner:'시스템 담당 G',exposed:false,critical:'중',updated:'2026-10-28'},
	{id:'SYS-009',department:'기록관리과',name:'전자기록 검색 시스템',lang:'C#',product:'Demo Framework',version:'3.2.5',owner:'시스템 담당 H',exposed:false,critical:'중',updated:'2026-10-28'},
	{id:'SYS-010',department:'업무혁신과',name:'업무자동화 포털',lang:'Python',product:'Demo WAS',version:'',owner:'시스템 담당 I',exposed:false,critical:'중',updated:'2026-10-28'}
],feed:[],findings:[],alerts:[],logs:[],last:null,fail:false,settings:{time:'09:00',cvss:9,remind:3}});

const catalog=[{id:'DEMO-CVE-001',product:'Demo WAS',min:'9.0.0',max:'9.0.10',score:9.8,kev:true,summary:'요청 처리 과정의 원격 코드 실행 취약점',fix:'9.0.10',description:'9.0.0 이상 9.0.10 미만인 가상 제품에 적용됩니다.'},{id:'DEMO-CVE-002',product:'Demo Framework',min:'3.0.0',max:'3.2.5',score:8.1,kev:false,summary:'입력 검증 누락에 따른 권한 우회',fix:'3.2.5',description:'3.0.0 이상 3.2.5 미만인 가상 제품에 적용됩니다.'},{id:'DEMO-CVE-003',product:'Demo Runtime',min:'20.0.0',max:'20.0.9',score:6.5,kev:false,summary:'특정 요청에 의한 서비스 거부',fix:'20.0.9',description:'20.0.0 이상 20.0.9 미만인 가상 제품에 적용됩니다.'}];

function cmp(a,b){let aa=a.split('.').map(Number),bb=b.split('.').map(Number);for(let i=0;i<Math.max(aa.length,bb.length);i++){let d=(aa[i]||0)-(bb[i]||0);if(d)return Math.sign(d)}return 0}

function judge(a,c){if(!a.version)return {status:'판정 불가',reason:'설치 버전이 누락되어 영향 범위를 확인할 수 없습니다.'};if(!/^\d+(\.\d+)*$/.test(a.version))return {status:'영향 가능·확인 필요',reason:'시연용 숫자 버전 규칙으로 비교할 수 없는 버전입니다.'};let hit=cmp(a.version,c.min)>=0&&cmp(a.version,c.max)<0;return {status:hit?'영향 대상':'비해당',reason:`설치 ${a.version} / 영향 범위 ${c.min} 이상 ${c.max} 미만 · ${hit?'범위에 포함':'범위 밖'}`}}
