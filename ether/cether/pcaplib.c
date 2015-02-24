/*
###########################################################################
*/
#include <Python.h>
#include <structmember.h>
#include <stdint.h>
#include <openssl/hmac.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <zlib.h>
#include <pcap.h>
#include "pcaplib.h"

static int
PcapDevice_init(PcapDevice *self, PyObject *args, PyObject *kwds)
{
    self->device_name = Py_None;
    Py_INCREF(Py_None);
    
    self->type = Py_None;
    Py_INCREF(Py_None);

    self->datalink_name = Py_None;
    Py_INCREF(Py_None);
    
    self->p = NULL;
    self->status = self->datalink = 0;
    
    return 0;
}

static void
PcapDevice_dealloc(PcapDevice *self)
{
    Py_XDECREF(self->device_name);
    Py_XDECREF(self->type);
    Py_XDECREF(self->datalink_name);
    if (self->p && self->status == 1)
        pcap_close(self->p);
    self->ob_type->tp_free((PyObject*)self);
}

PyDoc_STRVAR(PcapDevice_close__doc__,
    "close() -> None\n\n"
    "Close the instance");
static PyObject*
PcapDevice_close(PcapDevice *self, PyObject *args)
{
    if (self->status == 1)
        pcap_close(self->p);
    self->status = -1;

    Py_INCREF(Py_None);
    return Py_None;
}

static int
PcapDevice_setup(PcapDevice *self, const char* type, const char* dev)
{
    const char *dlink_name;

    self->datalink = pcap_datalink(self->p);
    
    dlink_name = pcap_datalink_val_to_name(self->datalink);
    if (dlink_name)
    {
        Py_DECREF(self->datalink_name);
        self->datalink_name = PyString_FromString(dlink_name);
        if (!self->datalink_name)
        {
            PyErr_NoMemory();
            return 0;
        }
    }

    Py_DECREF(self->type);
    self->type = PyString_FromString(type);
    if (!self->type)
    {
        PyErr_NoMemory();
        return 0;
    }
    
    Py_DECREF(self->device_name);
    self->device_name = PyString_FromString(dev);
    if (!self->device_name)
    {
        PyErr_NoMemory();
        return 0;
    }
    
    self->status = 1;

    return 1;
}

PyDoc_STRVAR(PcapDevice_open_live__doc__,
    "open_live(device_name) -> None\n\n"
    "Open a device for live-capture");
static PyObject*
PcapDevice_open_live(PcapDevice *self, PyObject *args)
{
    char errbuf[PCAP_ERRBUF_SIZE], *device_name;

    if (!PyArg_ParseTuple(args, "s", &device_name))
        return NULL;

    if (self->status != 0)
    {
        PyErr_SetString(PyExc_RuntimeError, "Already opened.");
        return NULL;
    }

    self->p = pcap_open_live(device_name, 65535, 1, 200, errbuf);
    if (!self->p)
    {
        PyErr_Format(PyExc_IOError, "Failed to open device '%s' (libpcap: %s)", device_name, errbuf);
        return NULL;
    }
    
    if (!PcapDevice_setup(self, "live", device_name))
        return NULL;
    
    Py_INCREF(Py_None);
    return Py_None;
}

PyDoc_STRVAR(PcapDevice_open_offline__doc__,
    "open_offline(fname) ->None\n\n"
    "Open a file for reading");
static PyObject*
PcapDevice_open_offline(PcapDevice *self, PyObject *args)
{
    char errbuf[PCAP_ERRBUF_SIZE], *fname;
    
    if (!PyArg_ParseTuple(args, "s", &fname))
        return NULL;

    if (self->status != 0)
    {
        PyErr_SetString(PyExc_RuntimeError, "Already opened.");
        return NULL;
    }

    self->p = pcap_open_offline(fname, errbuf);
    if (!self->p)
    {
        PyErr_Format(PyExc_IOError, "Failed to open file '%s' (libpcap: %s)", fname, errbuf);
        return NULL;
    }
    
    if (!PcapDevice_setup(self, "offline", fname))
        return NULL;

    Py_INCREF(Py_None);
    return Py_None;
}

PyDoc_STRVAR(PcapDevice_read__doc__,
    "read() -> tuple\n\n"
    "Read the next packet");
static PyObject*
PcapDevice_read(PcapDevice *self, PyObject *args)
{
    PyObject *result, *ts, *pckt_content;
    int ret;
    struct pcap_pkthdr *h;
    const u_char *bytes;
    
    if (self->status != 1)
    {
        PyErr_SetString(PyExc_RuntimeError, "Instance not ready for reading.");
        return NULL;
    }

    for (;;)
    {
        Py_BEGIN_ALLOW_THREADS;
        ret = pcap_next_ex(self->p, &h, &bytes);
        Py_END_ALLOW_THREADS;
        switch (ret)
        {
            case 0: // Timeout from live-capture
                PyErr_CheckSignals();
                if (PyErr_Occurred())
                    return NULL;
                continue;
            case 1: // OK
                pckt_content = PyString_FromStringAndSize((char*)bytes, h->caplen);
                if (!pckt_content)
                    return PyErr_NoMemory();
                
                ts = PyTuple_New(2);
                if (!ts)
                {
                    Py_DECREF(pckt_content);
                    return PyErr_NoMemory();
                }
                PyTuple_SetItem(ts, 0, PyLong_FromLong(h->ts.tv_sec));
                PyTuple_SetItem(ts, 1, PyLong_FromLong(h->ts.tv_usec));
                
                result = PyTuple_New(2);
                if (!result)
                {
                    Py_DECREF(pckt_content);
                    Py_DECREF(ts);
                    return PyErr_NoMemory();
                }
                PyTuple_SetItem(result, 0, ts);
                PyTuple_SetItem(result, 1, pckt_content);
                
                return result;
                
            case -2: // End of file
                Py_INCREF(Py_None);
                return Py_None;
            case -1: // Error
                PyErr_Format(PyExc_IOError, "libpcap-error while reading: %s", pcap_geterr(self->p));
                return NULL;
            default:
                PyErr_SetString(PyExc_IOError, "Unknown return-value from pcap_next_ex()");
                return NULL;
        }
    }

}

PyDoc_STRVAR(PcapDevice_send__doc__,
    "send(object) -> None\n\n"
    "Send an object's string-representation as a raw packet via a live device.");
static PyObject*
PcapDevice_send(PcapDevice *self, PyObject *args)
{
    char *pckt_buffer;
    Py_ssize_t pckt_size;
    PyObject *pckt, *pckt_string;
    
    if (self->status != 1)
    {
        PyErr_SetString(PyExc_RuntimeError, "Instance not ready for writing.");
        return NULL;
    }

    if (!PyArg_ParseTuple(args, "O", &pckt))
        return NULL;

    pckt_string = PyObject_Str(pckt);
    if (!pckt_string)
    {
        PyErr_SetString(PyExc_ValueError, "Failed to get string-representation from object.");
        return NULL;
    }

    if (PyString_AsStringAndSize(pckt_string, &pckt_buffer, &pckt_size))
    {
        Py_DECREF(pckt_string);
        return NULL;
    }

    if (pcap_sendpacket(self->p, (unsigned char*)pckt_buffer, pckt_size))
    {
        PyErr_Format(PyExc_IOError, "Failed to send packet (libpcap: %s).", pcap_geterr(self->p));
        Py_DECREF(pckt_string);
        return NULL;
    }
    
    Py_DECREF(pckt_string);
    
    Py_INCREF(Py_None);
    return Py_None;
}

PyDoc_STRVAR(PcapDevice_set_filter__doc__,
    "set_filter(filter_string) -> None\n\n"
    "Set a BPF-filter");
static PyObject*
PcapDevice_set_filter(PcapDevice *self, PyObject *args)
{
    struct bpf_program fp;
    char *filter_string;

    if (!PyArg_ParseTuple(args, "s", &filter_string))
        return NULL;
    
    if (self->status != 1)
    {
        PyErr_SetString(PyExc_RuntimeError, "Instance not opened yet");
        return NULL;
    }

    if (pcap_compile(self->p, &fp, filter_string, 0, 0))
    {
        PyErr_Format(PyExc_ValueError, "Failed to compile BPF-filter (libpcap: %s).", pcap_geterr(self->p));
        return NULL;
    }

    if (pcap_setfilter(self->p, &fp))
    {
        PyErr_Format(PyExc_RuntimeError, "Failed to set BPF-filter (libpcap: %s)", pcap_geterr(self->p));
        pcap_freecode(&fp);
        return NULL;
    }
    pcap_freecode(&fp);

    Py_INCREF(Py_None);
    return Py_None;
}



static PyMemberDef PcapDevice_members[] =
{
    {"deviceName", T_OBJECT, offsetof(PcapDevice, device_name), READONLY},
    {"type", T_OBJECT, offsetof(PcapDevice, type), READONLY},
    {"datalink", T_INT, offsetof(PcapDevice, datalink), READONLY},
    {"datalink_name", T_OBJECT, offsetof(PcapDevice, datalink_name), READONLY},
    {NULL}
};

static PyMethodDef PcapDevice_methods[] =
{
    {"open_live", (PyCFunction)PcapDevice_open_live, METH_VARARGS, PcapDevice_open_live__doc__},
    {"open_offline", (PyCFunction)PcapDevice_open_offline, METH_VARARGS, PcapDevice_open_offline__doc__},
    {"close", (PyCFunction)PcapDevice_close, METH_NOARGS, PcapDevice_close__doc__},
    {"read", (PyCFunction)PcapDevice_read, METH_NOARGS, PcapDevice_read__doc__},
    {"send", (PyCFunction)PcapDevice_send, METH_VARARGS, PcapDevice_send__doc__},
    {"set_filter", (PyCFunction)PcapDevice_set_filter, METH_VARARGS, PcapDevice_set_filter__doc__},
    {NULL, NULL}
};

static PyTypeObject PcapDevice_type = {
    PyObject_HEAD_INIT(NULL)
    0,                          /*ob_size*/
    "pcaplib.PcapDevice",   /*tp_name*/
    sizeof(PcapDevice),         /*tp_basicsize*/
    0,                          /*tp_itemsize*/
    (destructor)PcapDevice_dealloc, /*tp_dealloc*/
    0,                          /*tp_print*/
    0,                          /*tp_getattr*/
    0,                          /*tp_setattr*/
    0,                          /*tp_compare*/
    0,                          /*tp_repr*/
    0,                          /*tp_as_number*/
    0,                          /*tp_as_sequence*/
    0,                          /*tp_as_mapping*/
    0,                          /*tp_hash*/
    0,                          /*tp_call*/
    0,                          /*tp_str*/
    0,                          /*tp_getattro*/
    0,                          /*tp_setattro*/
    0,                          /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT          /*tp_flags*/
    | Py_TPFLAGS_BASETYPE,
    0,                          /*tp_doc*/
    0,                          /*tp_traverse*/
    0,                          /*tp_clear*/
    0,                          /*tp_richcompare*/
    0,                          /*tp_weaklistoffset*/
    0,                          /*tp_iter*/
    0,                          /*tp_iternext*/
    PcapDevice_methods,         /*tp_methods*/
    PcapDevice_members,         /*tp_members*/
    0,                          /*tp_getset*/
    0,                          /*tp_base*/
    0,                          /*tp_dict*/
    0,                          /*tp_descr_get*/
    0,                          /*tp_descr_set*/
    0,                          /*tp_dictoffset*/
    (initproc)PcapDevice_init,  /*tp_init*/
    0,                          /*tp_alloc*/
    0,                          /*tp_new*/
    0,                          /*tp_free*/
    0,                          /*tp_is_gc*/
};


/*
    ###########################################################################
    
    Module initialization
    
    ###########################################################################
*/

PyMODINIT_FUNC
initpcaplib(void)
{
    PyObject *m;

    PcapDevice_type.tp_getattro = PyObject_GenericGetAttr;
    PcapDevice_type.tp_setattro = PyObject_GenericSetAttr;
    PcapDevice_type.tp_alloc  = PyType_GenericAlloc;
    PcapDevice_type.tp_new = PyType_GenericNew;
    PcapDevice_type.tp_free = _PyObject_Del;
    if (PyType_Ready(&PcapDevice_type) < 0)
	    return;

    m = Py_InitModule("pcaplib", NULL);

    Py_INCREF(&PcapDevice_type);
    PyModule_AddObject(m, "PcapDevice", (PyObject*)&PcapDevice_type);
}
