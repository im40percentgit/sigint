var Q,b,bt,ie,P,vt,yt,$t,wt,ot,st,it,re,K={},X=[],oe=/acit|ex(?:s|g|n|p|$)|rph|grid|ows|mnc|ntw|ine[ch]|zoo|^ord|itera/i,Z=Array.isArray;function N(t,e){for(var n in e)t[n]=e[n];return t}function at(t){t&&t.parentNode&&t.parentNode.removeChild(t)}function k(t,e,n){var i,o,s,a={};for(s in e)s=="key"?i=e[s]:s=="ref"?o=e[s]:a[s]=e[s];if(arguments.length>2&&(a.children=arguments.length>3?Q.call(arguments,2):n),typeof t=="function"&&t.defaultProps!=null)for(s in t.defaultProps)a[s]===void 0&&(a[s]=t.defaultProps[s]);return q(t,a,i,o,null)}function q(t,e,n,i,o){var s={type:t,props:e,key:n,ref:i,__k:null,__:null,__b:0,__e:null,__c:null,constructor:void 0,__v:o??++bt,__i:-1,__u:0};return o==null&&b.vnode!=null&&b.vnode(s),s}function tt(t){return t.children}function J(t,e){this.props=t,this.context=e}function U(t,e){if(e==null)return t.__?U(t.__,t.__i+1):null;for(var n;e<t.__k.length;e++)if((n=t.__k[e])!=null&&n.__e!=null)return n.__e;return typeof t.type=="function"?U(t):null}function ae(t){if(t.__P&&t.__d){var e=t.__v,n=e.__e,i=[],o=[],s=N({},e);s.__v=e.__v+1,b.vnode&&b.vnode(s),lt(t.__P,s,e,t.__n,t.__P.namespaceURI,32&e.__u?[n]:null,i,n??U(e),!!(32&e.__u),o),s.__v=e.__v,s.__.__k[s.__i]=s,Ct(i,s,o),e.__e=e.__=null,s.__e!=n&&xt(s)}}function xt(t){if((t=t.__)!=null&&t.__c!=null)return t.__e=t.__c.base=null,t.__k.some(function(e){if(e!=null&&e.__e!=null)return t.__e=t.__c.base=e.__e}),xt(t)}function ht(t){(!t.__d&&(t.__d=!0)&&P.push(t)&&!Y.__r++||vt!=b.debounceRendering)&&((vt=b.debounceRendering)||yt)(Y)}function Y(){for(var t,e=1;P.length;)P.length>e&&P.sort($t),t=P.shift(),e=P.length,ae(t);Y.__r=0}function kt(t,e,n,i,o,s,a,c,_,l,d){var r,p,u,v,f,y,h,g=i&&i.__k||X,E=e.length;for(_=le(n,e,g,_,E),r=0;r<E;r++)(u=n.__k[r])!=null&&(p=u.__i!=-1&&g[u.__i]||K,u.__i=r,y=lt(t,u,p,o,s,a,c,_,l,d),v=u.__e,u.ref&&p.ref!=u.ref&&(p.ref&&ct(p.ref,null,u),d.push(u.ref,u.__c||v,u)),f==null&&v!=null&&(f=v),(h=!!(4&u.__u))||p.__k===u.__k?_=St(u,_,t,h):typeof u.type=="function"&&y!==void 0?_=y:v&&(_=v.nextSibling),u.__u&=-7);return n.__e=f,_}function le(t,e,n,i,o){var s,a,c,_,l,d=n.length,r=d,p=0;for(t.__k=new Array(o),s=0;s<o;s++)(a=e[s])!=null&&typeof a!="boolean"&&typeof a!="function"?(typeof a=="string"||typeof a=="number"||typeof a=="bigint"||a.constructor==String?a=t.__k[s]=q(null,a,null,null,null):Z(a)?a=t.__k[s]=q(tt,{children:a},null,null,null):a.constructor===void 0&&a.__b>0?a=t.__k[s]=q(a.type,a.props,a.key,a.ref?a.ref:null,a.__v):t.__k[s]=a,_=s+p,a.__=t,a.__b=t.__b+1,c=null,(l=a.__i=ce(a,n,_,r))!=-1&&(r--,(c=n[l])&&(c.__u|=2)),c==null||c.__v==null?(l==-1&&(o>d?p--:o<d&&p++),typeof a.type!="function"&&(a.__u|=4)):l!=_&&(l==_-1?p--:l==_+1?p++:(l>_?p--:p++,a.__u|=4))):t.__k[s]=null;if(r)for(s=0;s<d;s++)(c=n[s])!=null&&!(2&c.__u)&&(c.__e==i&&(i=U(c)),Lt(c,c));return i}function St(t,e,n,i){var o,s;if(typeof t.type=="function"){for(o=t.__k,s=0;o&&s<o.length;s++)o[s]&&(o[s].__=t,e=St(o[s],e,n,i));return e}t.__e!=e&&(i&&(e&&t.type&&!e.parentNode&&(e=U(t)),n.insertBefore(t.__e,e||null)),e=t.__e);do e=e&&e.nextSibling;while(e!=null&&e.nodeType==8);return e}function ce(t,e,n,i){var o,s,a,c=t.key,_=t.type,l=e[n],d=l!=null&&(2&l.__u)==0;if(l===null&&c==null||d&&c==l.key&&_==l.type)return n;if(i>(d?1:0)){for(o=n-1,s=n+1;o>=0||s<e.length;)if((l=e[a=o>=0?o--:s++])!=null&&!(2&l.__u)&&c==l.key&&_==l.type)return a}return-1}function mt(t,e,n){e[0]=="-"?t.setProperty(e,n??""):t[e]=n==null?"":typeof n!="number"||oe.test(e)?n:n+"px"}function z(t,e,n,i,o){var s,a;t:if(e=="style")if(typeof n=="string")t.style.cssText=n;else{if(typeof i=="string"&&(t.style.cssText=i=""),i)for(e in i)n&&e in n||mt(t.style,e,"");if(n)for(e in n)i&&n[e]==i[e]||mt(t.style,e,n[e])}else if(e[0]=="o"&&e[1]=="n")s=e!=(e=e.replace(wt,"$1")),a=e.toLowerCase(),e=a in t||e=="onFocusOut"||e=="onFocusIn"?a.slice(2):e.slice(2),t.l||(t.l={}),t.l[e+s]=n,n?i?n.u=i.u:(n.u=ot,t.addEventListener(e,s?it:st,s)):t.removeEventListener(e,s?it:st,s);else{if(o=="http://www.w3.org/2000/svg")e=e.replace(/xlink(H|:h)/,"h").replace(/sName$/,"s");else if(e!="width"&&e!="height"&&e!="href"&&e!="list"&&e!="form"&&e!="tabIndex"&&e!="download"&&e!="rowSpan"&&e!="colSpan"&&e!="role"&&e!="popover"&&e in t)try{t[e]=n??"";break t}catch{}typeof n=="function"||(n==null||n===!1&&e[4]!="-"?t.removeAttribute(e):t.setAttribute(e,e=="popover"&&n==1?"":n))}}function gt(t){return function(e){if(this.l){var n=this.l[e.type+t];if(e.t==null)e.t=ot++;else if(e.t<n.u)return;return n(b.event?b.event(e):e)}}}function lt(t,e,n,i,o,s,a,c,_,l){var d,r,p,u,v,f,y,h,g,E,L,I,ft,j,nt,D=e.type;if(e.constructor!==void 0)return null;128&n.__u&&(_=!!(32&n.__u),s=[c=e.__e=n.__e]),(d=b.__b)&&d(e);t:if(typeof D=="function")try{if(h=e.props,g="prototype"in D&&D.prototype.render,E=(d=D.contextType)&&i[d.__c],L=d?E?E.props.value:d.__:i,n.__c?y=(r=e.__c=n.__c).__=r.__E:(g?e.__c=r=new D(h,L):(e.__c=r=new J(h,L),r.constructor=D,r.render=de),E&&E.sub(r),r.state||(r.state={}),r.__n=i,p=r.__d=!0,r.__h=[],r._sb=[]),g&&r.__s==null&&(r.__s=r.state),g&&D.getDerivedStateFromProps!=null&&(r.__s==r.state&&(r.__s=N({},r.__s)),N(r.__s,D.getDerivedStateFromProps(h,r.__s))),u=r.props,v=r.state,r.__v=e,p)g&&D.getDerivedStateFromProps==null&&r.componentWillMount!=null&&r.componentWillMount(),g&&r.componentDidMount!=null&&r.__h.push(r.componentDidMount);else{if(g&&D.getDerivedStateFromProps==null&&h!==u&&r.componentWillReceiveProps!=null&&r.componentWillReceiveProps(h,L),e.__v==n.__v||!r.__e&&r.shouldComponentUpdate!=null&&r.shouldComponentUpdate(h,r.__s,L)===!1){e.__v!=n.__v&&(r.props=h,r.state=r.__s,r.__d=!1),e.__e=n.__e,e.__k=n.__k,e.__k.some(function(F){F&&(F.__=e)}),X.push.apply(r.__h,r._sb),r._sb=[],r.__h.length&&a.push(r);break t}r.componentWillUpdate!=null&&r.componentWillUpdate(h,r.__s,L),g&&r.componentDidUpdate!=null&&r.__h.push(function(){r.componentDidUpdate(u,v,f)})}if(r.context=L,r.props=h,r.__P=t,r.__e=!1,I=b.__r,ft=0,g)r.state=r.__s,r.__d=!1,I&&I(e),d=r.render(r.props,r.state,r.context),X.push.apply(r.__h,r._sb),r._sb=[];else do r.__d=!1,I&&I(e),d=r.render(r.props,r.state,r.context),r.state=r.__s;while(r.__d&&++ft<25);r.state=r.__s,r.getChildContext!=null&&(i=N(N({},i),r.getChildContext())),g&&!p&&r.getSnapshotBeforeUpdate!=null&&(f=r.getSnapshotBeforeUpdate(u,v)),j=d!=null&&d.type===tt&&d.key==null?Et(d.props.children):d,c=kt(t,Z(j)?j:[j],e,n,i,o,s,a,c,_,l),r.base=e.__e,e.__u&=-161,r.__h.length&&a.push(r),y&&(r.__E=r.__=null)}catch(F){if(e.__v=null,_||s!=null)if(F.then){for(e.__u|=_?160:128;c&&c.nodeType==8&&c.nextSibling;)c=c.nextSibling;s[s.indexOf(c)]=null,e.__e=c}else{for(nt=s.length;nt--;)at(s[nt]);rt(e)}else e.__e=n.__e,e.__k=n.__k,F.then||rt(e);b.__e(F,e,n)}else s==null&&e.__v==n.__v?(e.__k=n.__k,e.__e=n.__e):c=e.__e=_e(n.__e,e,n,i,o,s,a,_,l);return(d=b.diffed)&&d(e),128&e.__u?void 0:c}function rt(t){t&&(t.__c&&(t.__c.__e=!0),t.__k&&t.__k.some(rt))}function Ct(t,e,n){for(var i=0;i<n.length;i++)ct(n[i],n[++i],n[++i]);b.__c&&b.__c(e,t),t.some(function(o){try{t=o.__h,o.__h=[],t.some(function(s){s.call(o)})}catch(s){b.__e(s,o.__v)}})}function Et(t){return typeof t!="object"||t==null||t.__b>0?t:Z(t)?t.map(Et):N({},t)}function _e(t,e,n,i,o,s,a,c,_){var l,d,r,p,u,v,f,y=n.props||K,h=e.props,g=e.type;if(g=="svg"?o="http://www.w3.org/2000/svg":g=="math"?o="http://www.w3.org/1998/Math/MathML":o||(o="http://www.w3.org/1999/xhtml"),s!=null){for(l=0;l<s.length;l++)if((u=s[l])&&"setAttribute"in u==!!g&&(g?u.localName==g:u.nodeType==3)){t=u,s[l]=null;break}}if(t==null){if(g==null)return document.createTextNode(h);t=document.createElementNS(o,g,h.is&&h),c&&(b.__m&&b.__m(e,s),c=!1),s=null}if(g==null)y===h||c&&t.data==h||(t.data=h);else{if(s=s&&Q.call(t.childNodes),!c&&s!=null)for(y={},l=0;l<t.attributes.length;l++)y[(u=t.attributes[l]).name]=u.value;for(l in y)u=y[l],l=="dangerouslySetInnerHTML"?r=u:l=="children"||l in h||l=="value"&&"defaultValue"in h||l=="checked"&&"defaultChecked"in h||z(t,l,null,u,o);for(l in h)u=h[l],l=="children"?p=u:l=="dangerouslySetInnerHTML"?d=u:l=="value"?v=u:l=="checked"?f=u:c&&typeof u!="function"||y[l]===u||z(t,l,u,y[l],o);if(d)c||r&&(d.__html==r.__html||d.__html==t.innerHTML)||(t.innerHTML=d.__html),e.__k=[];else if(r&&(t.innerHTML=""),kt(e.type=="template"?t.content:t,Z(p)?p:[p],e,n,i,g=="foreignObject"?"http://www.w3.org/1999/xhtml":o,s,a,s?s[0]:n.__k&&U(n,0),c,_),s!=null)for(l=s.length;l--;)at(s[l]);c||(l="value",g=="progress"&&v==null?t.removeAttribute("value"):v!=null&&(v!==t[l]||g=="progress"&&!v||g=="option"&&v!=y[l])&&z(t,l,v,y[l],o),l="checked",f!=null&&f!=t[l]&&z(t,l,f,y[l],o))}return t}function ct(t,e,n){try{if(typeof t=="function"){var i=typeof t.__u=="function";i&&t.__u(),i&&e==null||(t.__u=t(e))}else t.current=e}catch(o){b.__e(o,n)}}function Lt(t,e,n){var i,o;if(b.unmount&&b.unmount(t),(i=t.ref)&&(i.current&&i.current!=t.__e||ct(i,null,e)),(i=t.__c)!=null){if(i.componentWillUnmount)try{i.componentWillUnmount()}catch(s){b.__e(s,e)}i.base=i.__P=null}if(i=t.__k)for(o=0;o<i.length;o++)i[o]&&Lt(i[o],e,n||typeof t.type!="function");n||at(t.__e),t.__c=t.__=t.__e=void 0}function de(t,e,n){return this.constructor(t,n)}function Tt(t,e,n){var i,o,s,a;e==document&&(e=document.documentElement),b.__&&b.__(t,e),o=(i=typeof n=="function")?null:n&&n.__k||e.__k,s=[],a=[],lt(e,t=(!i&&n||e).__k=k(tt,null,[t]),o||K,K,e.namespaceURI,!i&&n?[n]:o?null:e.firstChild?Q.call(e.childNodes):null,s,!i&&n?n:o?o.__e:e.firstChild,i,a),Ct(s,t,a)}Q=X.slice,b={__e:function(t,e,n,i){for(var o,s,a;e=e.__;)if((o=e.__c)&&!o.__)try{if((s=o.constructor)&&s.getDerivedStateFromError!=null&&(o.setState(s.getDerivedStateFromError(t)),a=o.__d),o.componentDidCatch!=null&&(o.componentDidCatch(t,i||{}),a=o.__d),a)return o.__E=o}catch(c){t=c}throw t}},bt=0,ie=function(t){return t!=null&&t.constructor===void 0},J.prototype.setState=function(t,e){var n;n=this.__s!=null&&this.__s!=this.state?this.__s:this.__s=N({},this.state),typeof t=="function"&&(t=t(N({},n),this.props)),t&&N(n,t),t!=null&&this.__v&&(e&&this._sb.push(e),ht(this))},J.prototype.forceUpdate=function(t){this.__v&&(this.__e=!0,t&&this.__h.push(t),ht(this))},J.prototype.render=tt,P=[],yt=typeof Promise=="function"?Promise.prototype.then.bind(Promise.resolve()):setTimeout,$t=function(t,e){return t.__v.__b-e.__v.__b},Y.__r=0,wt=/(PointerCapture)$|Capture$/i,ot=0,st=gt(!1),it=gt(!0),re=0;var O,$,_t,Dt,B=0,Mt=[],w=b,Nt=w.__b,At=w.__r,Pt=w.diffed,Ht=w.__c,Rt=w.unmount,Ft=w.__;function ut(t,e){w.__h&&w.__h($,t,B||e),B=0;var n=$.__H||($.__H={__:[],__h:[]});return t>=n.__.length&&n.__.push({}),n.__[t]}function m(t){return B=1,ue(Bt,t)}function ue(t,e,n){var i=ut(O++,2);if(i.t=t,!i.__c&&(i.__=[n?n(e):Bt(void 0,e),function(c){var _=i.__N?i.__N[0]:i.__[0],l=i.t(_,c);_!==l&&(i.__N=[l,i.__[1]],i.__c.setState({}))}],i.__c=$,!$.__f)){var o=function(c,_,l){if(!i.__c.__H)return!0;var d=i.__c.__H.__.filter(function(p){return p.__c});if(d.every(function(p){return!p.__N}))return!s||s.call(this,c,_,l);var r=i.__c.props!==c;return d.some(function(p){if(p.__N){var u=p.__[0];p.__=p.__N,p.__N=void 0,u!==p.__[0]&&(r=!0)}}),s&&s.call(this,c,_,l)||r};$.__f=!0;var s=$.shouldComponentUpdate,a=$.componentWillUpdate;$.componentWillUpdate=function(c,_,l){if(this.__e){var d=s;s=void 0,o(c,_,l),s=d}a&&a.call(this,c,_,l)},$.shouldComponentUpdate=o}return i.__N||i.__}function x(t,e){var n=ut(O++,3);!w.__s&&Ot(n.__H,e)&&(n.__=t,n.u=e,$.__H.__h.push(n))}function Gt(t){return B=5,Wt(function(){return{current:t}},[])}function Wt(t,e){var n=ut(O++,7);return Ot(n.__H,e)&&(n.__=t(),n.__H=e,n.__h=t),n.__}function It(t,e){return B=8,Wt(function(){return t},e)}function pe(){for(var t;t=Mt.shift();){var e=t.__H;if(t.__P&&e)try{e.__h.some(et),e.__h.some(dt),e.__h=[]}catch(n){e.__h=[],w.__e(n,t.__v)}}}w.__b=function(t){$=null,Nt&&Nt(t)},w.__=function(t,e){t&&e.__k&&e.__k.__m&&(t.__m=e.__k.__m),Ft&&Ft(t,e)},w.__r=function(t){At&&At(t),O=0;var e=($=t.__c).__H;e&&(_t===$?(e.__h=[],$.__h=[],e.__.some(function(n){n.__N&&(n.__=n.__N),n.u=n.__N=void 0})):(e.__h.some(et),e.__h.some(dt),e.__h=[],O=0)),_t=$},w.diffed=function(t){Pt&&Pt(t);var e=t.__c;e&&e.__H&&(e.__H.__h.length&&(Mt.push(e)!==1&&Dt===w.requestAnimationFrame||((Dt=w.requestAnimationFrame)||fe)(pe)),e.__H.__.some(function(n){n.u&&(n.__H=n.u),n.u=void 0})),_t=$=null},w.__c=function(t,e){e.some(function(n){try{n.__h.some(et),n.__h=n.__h.filter(function(i){return!i.__||dt(i)})}catch(i){e.some(function(o){o.__h&&(o.__h=[])}),e=[],w.__e(i,n.__v)}}),Ht&&Ht(t,e)},w.unmount=function(t){Rt&&Rt(t);var e,n=t.__c;n&&n.__H&&(n.__H.__.some(function(i){try{et(i)}catch(o){e=o}}),n.__H=void 0,e&&w.__e(e,n.__v))};var Ut=typeof requestAnimationFrame=="function";function fe(t){var e,n=function(){clearTimeout(i),Ut&&cancelAnimationFrame(e),setTimeout(t)},i=setTimeout(n,35);Ut&&(e=requestAnimationFrame(n))}function et(t){var e=$,n=t.__c;typeof n=="function"&&(t.__c=void 0,n()),$=e}function dt(t){var e=$;t.__c=t.__(),$=e}function Ot(t,e){return!t||t.length!==e.length||e.some(function(n,i){return n!==t[i]})}function Bt(t,e){return typeof e=="function"?e(t):e}var jt=function(t,e,n,i){var o;e[0]=0;for(var s=1;s<e.length;s++){var a=e[s++],c=e[s]?(e[0]|=a?1:2,n[e[s++]]):e[++s];a===3?i[0]=c:a===4?i[1]=Object.assign(i[1]||{},c):a===5?(i[1]=i[1]||{})[e[++s]]=c:a===6?i[1][e[++s]]+=c+"":a?(o=t.apply(c,jt(t,c,n,["",null])),i.push(o),c[0]?e[0]|=2:(e[s-2]=0,e[s]=o)):i.push(c)}return i},Vt=new Map;function S(t){var e=Vt.get(this);return e||(e=new Map,Vt.set(this,e)),(e=jt(this,e.get(t)||(e.set(t,e=function(n){for(var i,o,s=1,a="",c="",_=[0],l=function(p){s===1&&(p||(a=a.replace(/^\s*\n\s*|\s*\n\s*$/g,"")))?_.push(0,p,a):s===3&&(p||a)?(_.push(3,p,a),s=2):s===2&&a==="..."&&p?_.push(4,p,0):s===2&&a&&!p?_.push(5,0,!0,a):s>=5&&((a||!p&&s===5)&&(_.push(s,0,a,o),s=6),p&&(_.push(s,p,0,o),s=6)),a=""},d=0;d<n.length;d++){d&&(s===1&&l(),l(d));for(var r=0;r<n[d].length;r++)i=n[d][r],s===1?i==="<"?(l(),_=[_],s=3):a+=i:s===4?a==="--"&&i===">"?(s=1,a=""):a=i+a[0]:c?i===c?c="":a+=i:i==='"'||i==="'"?c=i:i===">"?(l(),s=1):s&&(i==="="?(s=5,o=a,a=""):i==="/"&&(s<5||n[d][r+1]===">")?(l(),s===3&&(_=_[0]),s=_,(_=_[0]).push(2,0,s),s=0):i===" "||i==="	"||i===`
`||i==="\r"?(l(),s=2):a+=i),s===3&&a==="!--"&&(s=4,_=_[0])}return l(),_}(t)),e),arguments,[])).length>1?e:e[0]}var ve="";async function M(t,e,n){let i={method:t,headers:{"Content-Type":"application/json"}};n!==void 0&&(i.body=JSON.stringify(n));let o=await fetch(ve+e,i);if(!o.ok){let a=await o.text().catch(()=>o.statusText);throw new Error(`${t} ${e} \u2192 ${o.status}: ${a}`)}return(o.headers.get("content-type")||"").includes("application/json")?o.json():o.text()}function A(){return M("GET","/api/sessions")}function zt(t){return M("GET",`/api/sessions/${t}`)}function qt(t){return M("DELETE",`/api/sessions/${t}`)}function V(t){return M("GET",`/api/sessions/${t}/assets`)}function pt(t){return M("GET",`/api/sessions/${t}/findings`)}function Jt(t,e="markdown",n="detailed"){return M("GET",`/api/report/${t}?format=${e}&template=${n}`)}var H=S.bind(k);function Kt(){let[t,e]=m(null),[n,i]=m(null);if(x(()=>{A().then(e).catch(_=>i(_.message))},[]),n)return H`<div class="error-banner">${n}</div>`;if(!t)return H`<div class="loading">Loading...</div>`;let o=t.filter(_=>_.status==="active"||_.status==="running"),s=t.slice(0,5),a=t.length,c=o.length;return H`
    <div>
      <div class="page-header">
        <div>
          <div class="page-title">Dashboard</div>
          <div class="page-subtitle">SIGINT pentest intelligence platform</div>
        </div>
      </div>

      <div class="grid-4" style="margin-bottom: 1.5rem;">
        <div class="card">
          <div class="stat-value">${a}</div>
          <div class="stat-label">Total Sessions</div>
        </div>
        <div class="card">
          <div class="stat-value text-green">${c}</div>
          <div class="stat-label">Active Scans</div>
        </div>
        <div class="card">
          <div class="stat-value text-accent">--</div>
          <div class="stat-label">Findings Today</div>
        </div>
        <div class="card">
          <div class="stat-value text-blue">--</div>
          <div class="stat-label">Assets Discovered</div>
        </div>
      </div>

      <div class="card">
        <div class="card-header">
          <span class="card-title">Recent Sessions</span>
          <a href="#/sessions" class="btn btn-sm">View All</a>
        </div>
        ${s.length===0?H`<div class="empty-state">No sessions yet.<br/><br/>Start a scan from the CLI to see data here.</div>`:H`
            <table>
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Target</th>
                  <th>Status</th>
                  <th>Created</th>
                </tr>
              </thead>
              <tbody>
                ${s.map(_=>H`
                  <tr>
                    <td><a href=${"#/sessions/"+_.id} style="color:var(--blue);text-decoration:none;">${_.name}</a></td>
                    <td class="text-dim">${_.target||"\u2014"}</td>
                    <td><${he} status=${_.status} /></td>
                    <td class="text-dim">${me(_.created_at)}</td>
                  </tr>
                `)}
              </tbody>
            </table>
          `}
      </div>
    </div>
  `}function he({status:t}){return H`<span class=${"badge "+(t==="active"||t==="running"?"badge-active":t==="complete"||t==="completed"?"badge-low":"badge-info")}>${t||"unknown"}</span>`}function me(t){if(!t)return"\u2014";try{return new Date(t).toLocaleString(void 0,{month:"short",day:"numeric",hour:"2-digit",minute:"2-digit"})}catch{return t}}var R=S.bind(k);function Xt(){let[t,e]=m(null),[n,i]=m(null),[o,s]=m(""),[a,c]=m(null),_=It(()=>{i(null),A().then(e).catch(r=>i(r.message))},[]);x(()=>{_()},[_]);async function l(r,p){if(confirm(`Delete session "${p}"? This cannot be undone.`)){c(r);try{await qt(r),e(u=>u.filter(v=>v.id!==r))}catch(u){i(u.message)}finally{c(null)}}}let d=t?t.filter(r=>!o||r.name?.toLowerCase().includes(o.toLowerCase())||r.target?.toLowerCase().includes(o.toLowerCase())):[];return R`
    <div>
      <div class="page-header">
        <div>
          <div class="page-title">Sessions</div>
          <div class="page-subtitle">${t?t.length:"\u2026"} total sessions</div>
        </div>
        <button class="btn" onClick=${_}>Refresh</button>
      </div>

      ${n&&R`<div class="error-banner">${n}</div>`}

      <div class="card">
        <div class="card-header">
          <span class="card-title">All Sessions</span>
          <input
            class="input"
            placeholder="Filter by name or target…"
            value=${o}
            onInput=${r=>s(r.target.value)}
            style="width: 260px;"
          />
        </div>

        ${t?d.length===0?R`<div class="empty-state">${o?"No sessions match that filter.":"No sessions yet."}</div>`:R`
            <table>
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Target</th>
                  <th>Status</th>
                  <th>Created</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                ${d.map(r=>R`
                  <tr>
                    <td>
                      <a href=${"#/sessions/"+r.id} style="color:var(--blue);text-decoration:none;">
                        ${r.name}
                      </a>
                    </td>
                    <td class="text-dim">${r.target||"\u2014"}</td>
                    <td><${ge} status=${r.status} /></td>
                    <td class="text-dim">${be(r.created_at)}</td>
                    <td>
                      <button
                        class="btn btn-sm btn-danger"
                        disabled=${a===r.id}
                        onClick=${()=>l(r.id,r.name)}
                      >
                        ${a===r.id?"Deleting\u2026":"Delete"}
                      </button>
                    </td>
                  </tr>
                `)}
              </tbody>
            </table>
          `:R`<div class="loading">Loading sessions…</div>`}
      </div>
    </div>
  `}function ge({status:t}){return R`<span class=${"badge "+(t==="active"||t==="running"?"badge-active":t==="complete"||t==="completed"?"badge-low":"badge-info")}>${t||"unknown"}</span>`}function be(t){if(!t)return"\u2014";try{return new Date(t).toLocaleString(void 0,{month:"short",day:"numeric",hour:"2-digit",minute:"2-digit"})}catch{return t}}var C=S.bind(k),Yt=200;function Qt({sessionId:t,ws:e}){let[n,i]=m(null),[o,s]=m([]),[a,c]=m([]),[_,l]=m([]),[d,r]=m(null),p=Gt(null);return x(()=>{t&&Promise.all([zt(t),V(t),pt(t)]).then(([u,v,f])=>{i(u),s(v),c(f)}).catch(u=>r(u.message))},[t]),x(()=>e?e.subscribe(v=>{if(v.type!=="event")return;let f=v.data;f.session_id&&f.session_id!==t||(l(y=>{let h=[...y,{...f,_ts:new Date().toISOString()}];return h.length>Yt?h.slice(-Yt):h}),f.kind==="asset_found"&&V(t).then(s).catch(()=>{}),f.kind==="finding"&&pt(t).then(c).catch(()=>{}))}):void 0,[e,t]),x(()=>{p.current&&(p.current.scrollTop=p.current.scrollHeight)},[_]),d?C`<div class="error-banner">${d}</div>`:n?C`
    <div>
      <div class="page-header">
        <div>
          <div class="page-title">${n.name}</div>
          <div class="page-subtitle">Target: ${n.target||"\u2014"}</div>
        </div>
        <div style="display:flex;gap:0.5rem;">
          <a href=${"#/reports/"+t} class="btn btn-sm">Generate Report</a>
          <a href="#/sessions" class="btn btn-sm">← Back</a>
        </div>
      </div>

      <div class="grid-3" style="margin-bottom:1.5rem;">
        <div class="card">
          <div class="stat-value">${a.length}</div>
          <div class="stat-label">Findings</div>
        </div>
        <div class="card">
          <div class="stat-value">${o.length}</div>
          <div class="stat-label">Assets</div>
        </div>
        <div class="card">
          <div class="stat-value">${_.length}</div>
          <div class="stat-label">Events (live)</div>
        </div>
      </div>

      <!-- Live event log -->
      <div class="card" style="margin-bottom:1rem;">
        <div class="card-header">
          <span class="card-title">Live Event Stream</span>
          <button class="btn btn-sm" onClick=${()=>l([])}>Clear</button>
        </div>
        <div class="event-log" ref=${p}>
          ${_.length===0?C`<div class="text-dim" style="text-align:center;padding:1rem;">Waiting for events…</div>`:_.map((u,v)=>C`
              <div class="event-entry" key=${v}>
                <span class="event-time">${$e(u._ts)}</span>
                <span class="event-kind">${u.kind||"event"}</span>
                <span class="event-body">${we(u)}</span>
              </div>
            `)}
        </div>
      </div>

      <!-- Findings -->
      <div class="card" style="margin-bottom:1rem;">
        <div class="card-header">
          <span class="card-title">Findings (${a.length})</span>
        </div>
        ${a.length===0?C`<div class="empty-state">No findings yet.</div>`:C`
            <table>
              <thead><tr><th>Severity</th><th>Title</th><th>Asset</th></tr></thead>
              <tbody>
                ${a.map((u,v)=>C`
                  <tr key=${v}>
                    <td><${ye} sev=${u.severity} /></td>
                    <td>${u.title}</td>
                    <td class="text-dim">${u.asset||"\u2014"}</td>
                  </tr>
                `)}
              </tbody>
            </table>
          `}
      </div>

      <!-- Assets -->
      <div class="card">
        <div class="card-header">
          <span class="card-title">Assets (${o.length})</span>
        </div>
        ${o.length===0?C`<div class="empty-state">No assets discovered yet.</div>`:C`
            <table>
              <thead><tr><th>Kind</th><th>Value</th></tr></thead>
              <tbody>
                ${o.map((u,v)=>C`
                  <tr key=${v}>
                    <td><span class="badge badge-info">${u.kind}</span></td>
                    <td class="mono">${u.value}</td>
                  </tr>
                `)}
              </tbody>
            </table>
          `}
      </div>
    </div>
  `:C`<div class="loading">Loading session…</div>`}function ye({sev:t}){let e=(t||"").toLowerCase();return C`<span class=${"badge "+(e==="critical"?"badge-critical":e==="high"?"badge-high":e==="medium"?"badge-medium":e==="low"?"badge-low":"badge-info")}>${t||"info"}</span>`}function $e(t){if(!t)return"";try{return new Date(t).toLocaleTimeString()}catch{return""}}function we(t){if(t.message)return t.message;if(t.data&&typeof t.data=="string")return t.data;if(t.data)return JSON.stringify(t.data).slice(0,120);let{kind:e,session_id:n,_ts:i,...o}=t,s=JSON.stringify(o);return s.length>120?s.slice(0,117)+"\u2026":s}var G=S.bind(k);function Zt(){let[t,e]=m(null),[n,i]=m(null),[o,s]=m("");if(x(()=>{A().then(l=>Promise.all(l.map(d=>V(d.id).then(r=>r.map(p=>({...p,sessionName:d.name}))).catch(()=>[])))).then(l=>{let d=l.flat();e(d)}).catch(l=>i(l.message))},[]),n)return G`<div class="error-banner">${n}</div>`;if(!t)return G`<div class="loading">Loading assets…</div>`;let a=o?t.filter(l=>l.value?.toLowerCase().includes(o.toLowerCase())||l.kind?.toLowerCase().includes(o.toLowerCase())):t,c={};for(let l of a)(c[l.kind]=c[l.kind]||[]).push(l);let _=Object.keys(c).sort();return G`
    <div>
      <div class="page-header">
        <div>
          <div class="page-title">Assets</div>
          <div class="page-subtitle">${t.length} total across all sessions</div>
        </div>
        <input
          class="input"
          placeholder="Filter assets…"
          value=${o}
          onInput=${l=>s(l.target.value)}
          style="width: 240px;"
        />
      </div>

      ${_.length===0?G`
          <div class="card">
            <div class="empty-state">
              ${o?"No assets match that filter.":"No assets discovered yet."}
            </div>
          </div>
        `:_.map(l=>G`
          <div class="card" key=${l} style="margin-bottom:1rem;">
            <div class="card-header">
              <span class="card-title">${l}</span>
              <span class="text-dim" style="font-size:12px;">${c[l].length} asset${c[l].length!==1?"s":""}</span>
            </div>
            <table>
              <thead>
                <tr>
                  <th>Value</th>
                  <th>Session</th>
                </tr>
              </thead>
              <tbody>
                ${c[l].map((d,r)=>G`
                  <tr key=${r}>
                    <td class="mono">${d.value}</td>
                    <td class="text-dim">${d.sessionName||"\u2014"}</td>
                  </tr>
                `)}
              </tbody>
            </table>
          </div>
        `)}
    </div>
  `}var W=S.bind(k);function te(){let[t,e]=m(null),[n,i]=m(""),[o,s]=m("markdown"),[a,c]=m("detailed"),[_,l]=m(!1),[d,r]=m(null),[p,u]=m(null);x(()=>{A().then(f=>{e(f),f.length>0&&i(f[0].id)}).catch(f=>u(f.message))},[]);async function v(f){if(n){l(!0),u(null),r(null);try{let y=await Jt(n,o,a);if(f){let h=o==="html"?"html":"md",g=new Blob([y],{type:o==="html"?"text/html":"text/markdown"}),E=URL.createObjectURL(g),L=document.createElement("a");L.href=E,L.download=`sigint-report-${n.slice(0,8)}.${h}`,L.click(),URL.revokeObjectURL(E)}else r(y)}catch(y){u(y.message)}finally{l(!1)}}}return W`
    <div>
      <div class="page-header">
        <div>
          <div class="page-title">Reports</div>
          <div class="page-subtitle">Generate markdown or HTML reports for any session</div>
        </div>
      </div>

      ${p&&W`<div class="error-banner">${p}</div>`}

      <div class="card" style="margin-bottom:1rem;">
        <div class="card-header">
          <span class="card-title">Report Options</span>
        </div>

        <div style="display:flex;flex-direction:column;gap:1rem;">
          <div style="display:flex;gap:1rem;align-items:center;flex-wrap:wrap;">
            <label style="display:flex;flex-direction:column;gap:4px;font-size:12px;color:var(--text-dim);">
              Session
              <select
                class="input"
                value=${n}
                onChange=${f=>i(f.target.value)}
                style="min-width:200px;"
                disabled=${!t}
              >
                ${t?t.length===0?W`<option value="">No sessions</option>`:t.map(f=>W`<option value=${f.id} key=${f.id}>${f.name}</option>`):W`<option>Loading…</option>`}
              </select>
            </label>

            <label style="display:flex;flex-direction:column;gap:4px;font-size:12px;color:var(--text-dim);">
              Format
              <select class="input" value=${o} onChange=${f=>s(f.target.value)}>
                <option value="markdown">Markdown</option>
                <option value="html">HTML</option>
              </select>
            </label>

            <label style="display:flex;flex-direction:column;gap:4px;font-size:12px;color:var(--text-dim);">
              Template
              <select class="input" value=${a} onChange=${f=>c(f.target.value)}>
                <option value="executive">Executive</option>
                <option value="detailed">Detailed</option>
                <option value="technical">Technical</option>
              </select>
            </label>
          </div>

          <div style="display:flex;gap:0.75rem;">
            <button
              class="btn btn-primary"
              onClick=${()=>v(!1)}
              disabled=${_||!n}
            >
              ${_?"Generating\u2026":"Preview"}
            </button>
            <button
              class="btn"
              onClick=${()=>v(!0)}
              disabled=${_||!n}
            >
              Download
            </button>
          </div>
        </div>
      </div>

      ${d&&W`
        <div class="card">
          <div class="card-header">
            <span class="card-title">Preview</span>
            <button class="btn btn-sm" onClick=${()=>r(null)}>Close</button>
          </div>
          <pre style="white-space:pre-wrap;font-size:12px;line-height:1.7;color:var(--text);overflow-x:auto;">${d}</pre>
        </div>
      `}
    </div>
  `}var xe=`${location.protocol==="https:"?"wss":"ws"}://${location.host}/ws/events`,ee=1e3,ke=3e4;function ne(){let t=new Set,e=null,n=ee,i=!1,o="disconnected";function s(){i||(o="connecting",a(),e=new WebSocket(xe),e.addEventListener("open",()=>{n=ee,o="connected",a()}),e.addEventListener("message",d=>{try{let r=JSON.parse(d.data);t.forEach(p=>p({type:"event",data:r}))}catch{}}),e.addEventListener("close",()=>{if(i)return;o="disconnected",a();let d=n;n=Math.min(n*2,ke),setTimeout(s,d)}),e.addEventListener("error",()=>{}))}function a(){t.forEach(d=>d({type:"status",status:o}))}function c(d){return t.add(d),d({type:"status",status:o}),()=>t.delete(d)}function _(){return o}function l(){i=!0,e&&e.close()}return s(),{subscribe:c,status:_,close:l}}var T=S.bind(k);function se(t){let e=t.replace(/^#\/?/,"")||"";if(!e)return{page:"dashboard",id:null};let n=e.split("/");return n[0]==="sessions"&&n[1]?{page:"scan",id:n[1]}:n[0]==="sessions"?{page:"sessions",id:null}:n[0]==="assets"?{page:"assets",id:null}:n[0]==="reports"&&n[1]?{page:"reports",id:n[1]}:n[0]==="reports"?{page:"reports",id:null}:{page:"dashboard",id:null}}function Se(){let[t,e]=m(()=>se(location.hash));return x(()=>{let n=()=>e(se(location.hash));return window.addEventListener("hashchange",n),()=>window.removeEventListener("hashchange",n)},[]),t}function Ce({ws:t}){let[e,n]=m("disconnected");x(()=>{if(t)return t.subscribe(s=>{s.type==="status"&&n(s.status)})},[t]);let i=e==="connected"?"Live":e==="connecting"?"Connecting\u2026":"Disconnected";return T`
    <div class="ws-indicator">
      <span class=${"ws-dot "+(e==="connected"?"connected":e==="connecting"?"":"error")}></span>
      <span class="text-dim">${i}</span>
    </div>
  `}function Ee({page:t,ws:e}){let n=(i,o,s)=>T`<a href=${i} class=${t===s?"active":""}>${o}</a>`;return T`
    <nav class="nav">
      <span class="nav-brand">SIGINT</span>
      ${n("#/","Dashboard","dashboard")}
      ${n("#/sessions","Sessions","sessions")}
      ${n("#/assets","Assets","assets")}
      ${n("#/reports","Reports","reports")}
      <${Ce} ws=${e} />
    </nav>
  `}function Le(){let t=Se(),[e]=m(()=>ne()),n;return t.page==="dashboard"?n=T`<${Kt} />`:t.page==="sessions"?n=T`<${Xt} />`:t.page==="scan"?n=T`<${Qt} sessionId=${t.id} ws=${e} />`:t.page==="assets"?n=T`<${Zt} />`:t.page==="reports"?n=T`<${te} />`:n=T`<div class="empty-state">Page not found.</div>`,T`
    <div id="app">
      <${Ee} page=${t.page} ws=${e} />
      <main class="main">
        ${n}
      </main>
    </div>
  `}Tt(T`<${Le} />`,document.getElementById("app"));
